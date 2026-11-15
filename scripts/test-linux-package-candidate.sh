#!/usr/bin/env bash
# Exercise the source-bound package delivery workflow on a disposable native Linux host.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# != 3 ]]; then
  echo "Usage: bash scripts/test-linux-package-candidate.sh ARCH EXPECTED_COMMIT ABSOLUTE_REPORT_DIRECTORY" >&2
  exit 2
fi
arch="$1"
expected_commit="$2"
report="$3"
export GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS= PYTHONDONTWRITEBYTECODE=1
case "$arch" in
  amd64) other=arm64; machine=x86_64 ;;
  arm64) other=amd64; machine=aarch64 ;;
  *) echo "Expected amd64 or arm64" >&2; exit 2 ;;
esac
if [[ "$(uname -s):$(uname -m)" != "Linux:$machine" || "$(dpkg --print-architecture)" != "$arch" ||
      "$(go env GOHOSTOS):$(go env GOHOSTARCH)" != "linux:$arch" ]]; then
  echo "Linux kernel, package tools and Go host architecture must match" >&2
  exit 1
fi
if [[ "$expected_commit" != "$(git rev-parse HEAD)" || -n "$(git status --porcelain)" ||
      "$report" != /* || -e "$report" || -L "$report" ]]; then
  echo "Expected the exact clean source commit and a fresh absolute report directory" >&2
  exit 1
fi

fixture="$(mktemp -d "${TMPDIR:-/tmp}/accessweaver-package-candidate.XXXXXXXX")"
trap 'rm -rf -- "$fixture"' EXIT
mkdir "$fixture/packages"
older_release="0.0.0-alpha.1"
newer_release="0.0.0-alpha.2"
older="${older_release%%-*}~${older_release#*-}"
newer="${newer_release%%-*}~${newer_release#*-}"
first="deb-fixture-old-$expected_commit"
second="deb-fixture-new-$expected_commit"
contact="AccessWeaver Fixture <package-fixture@example.invalid>"

build_archives() {
  local label="$1" version="$2"
  BUILD_VERSION="$version" bash scripts/package-release.sh "$label"
  python3 -B scripts/verify_release.py "dist/$label" --check-go-metadata
  python3 -B - "dist/$label/BUILD-MANIFEST.json" "$expected_commit" "$version" <<'PY'
import json
from pathlib import Path
import sys

path, expected, version = sys.argv[1:]
manifest = json.loads(Path(path).read_bytes())
if (manifest["sourceCommit"], manifest["sourceState"], manifest["version"]) != (expected, "clean", version):
    raise SystemExit("Portable fixture identity differs from the requested source and version")
PY
}
archive_path() {
  printf '%s/dist/%s/accessweaver-%s-linux-%s.tar.gz\n' "$PWD" "$1" "$1" "$2"
}
sha() {
  sha256sum -- "$1" | cut -d ' ' -f 1
}

build_archives "$first" "$older_release"
build_archives "$second" "$newer_release"

before="$(archive_path "$first" "$arch")"
after="$(archive_path "$second" "$arch")"
cross="$(archive_path "$second" "$other")"
privileged=()
if (( EUID != 0 )); then privileged=(sudo -n); fi
sandbox=("${privileged[@]}" unshare --mount --propagation private --net --pid --fork --mount-proc --kill-child)
"${sandbox[@]}" /usr/bin/python3 -B scripts/test-linux-deb-lifecycle.py --arch "$arch" \
  --old "$before" --old-sha256 "$(sha "$before")" --new "$after" --new-sha256 "$(sha "$after")" \
  --other "$cross" --other-sha256 "$(sha "$cross")" > "$fixture/dpkg.json"

pins=()
for label in "$first" "$second"; do
  for target in amd64 arm64; do
    archive="$(archive_path "$label" "$target")"
    package="$(python3 -B scripts/build-linux-deb.py "$archive" --arch "$target" --sha256 "$(sha "$archive")" \
      --maintainer "$contact" --output-directory "$fixture/packages")"
    pins+=(--package-sha256 "${package##*/}" "$(sha "$package")")
  done
done

"${sandbox[@]}" /bin/bash -c 'ip link set lo up && exec /usr/bin/python3 -B "$@"' aw-apt \
  scripts/test-linux-apt-repository.py "$fixture/packages" --arch "$arch" \
  --older-version "$older" --newer-version "$newer" "${pins[@]}" > "$fixture/apt.json"

python3 -B - "$fixture" "$report" "$expected_commit" "$arch" "$older" "$newer" <<'PY'
import hashlib
import json
from pathlib import Path
import sys

staging, destination, commit, arch, older, newer = sys.argv[1:]
staging, destination = Path(staging), Path(destination)
reports = {name: (staging / name).read_bytes() for name in ("dpkg.json", "apt.json")}
dpkg, apt = (json.loads(reports[name]) for name in ("dpkg.json", "apt.json"))
if any(item["endpointArchitecture"] != arch or item["productionQualificationComplete"] is not False
       for item in (dpkg, apt)):
    raise SystemExit("Package evidence does not match the native fixture scope")
binary_by_version = {}
for package in dpkg["packages"]:
    name = f'accessweaver_{package["version"]}_{package["arch"]}.deb'
    if apt["packageSHA256"].get(name) != package["debSHA256"]:
        raise SystemExit("dpkg and APT consumed different package bytes")
    if package["arch"] == arch:
        binary_by_version[package["version"]] = package["binarySHA256"]
if (apt["olderBinarySHA256"], apt["newerBinarySHA256"]) != (binary_by_version[older], binary_by_version[newer]):
    raise SystemExit("Installed APT binaries differ from the dpkg payloads")
summary = {
    "schemaVersion": 1,
    "sourceCommit": commit,
    "endpointArchitecture": arch,
    "fixtureVersions": [older, newer],
    "reportsSHA256": {name: hashlib.sha256(data).hexdigest() for name, data in reports.items()},
    "productionQualificationComplete": False,
}
destination.mkdir()
for name, data in reports.items():
    (destination / name).write_bytes(data)
(destination / "qualification.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
PY
