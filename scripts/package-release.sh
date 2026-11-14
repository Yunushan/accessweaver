#!/usr/bin/env bash
# Build unsigned, self-contained core archives with notices and checksums.
set -euo pipefail
cd "$(dirname "$0")/.."

# Resolve dependencies from this checkout and ignore per-user Go settings.
export GOENV=off GOWORK=off GOFLAGS=

release_label="${1:-preview}"
if [[ ! "$release_label" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
  echo "Release label may contain letters, digits, dots, underscores and hyphens." >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required for packaging." >&2; exit 1; }

# Build in a fresh private temporary directory, so old files never enter a release.
stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/accessweaver-release.XXXXXXXX")"
trap 'rm -rf "$stage_dir"' EXIT
GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" CGO_ENABLED=0 \
  go -C scripts/sbom-tools build -mod=readonly -trimpath -o "$stage_dir/sbom-schema" .
OUTPUT_DIR="$stage_dir/bin" bash scripts/build-all.sh

python3 - "$release_label" "$stage_dir/bin" <<'PY'
from pathlib import Path
import hashlib
import json
import platform
import re
import subprocess
import sys
import zlib
sys.path.insert(0, "scripts")
from release_archive import epoch_from_timestamp, write_archive
from sbom import generate

label, binaries = sys.argv[1], Path(sys.argv[2])
build_info = json.loads((binaries / "BUILD-INFO.json").read_text(encoding="utf-8"))
epoch = epoch_from_timestamp(build_info["builtAt"])
out = Path("dist") / label
out.mkdir(parents=True, exist_ok=True)
manifest = {
    "project": "AccessWeaver",
    "releaseLabel": label,
    "packaging": {"pythonVersion": platform.python_version(), "zlibVersion": zlib.ZLIB_VERSION,
                  "zlibRuntimeVersion": zlib.ZLIB_RUNTIME_VERSION, "archiveEpoch": epoch},
    "goVersion": subprocess.check_output(["go", "version"], text=True).strip(),
    "sourceCommit": build_info["commit"],
    "sourceState": build_info["sourceState"],
    "version": build_info["version"],
    "builtAt": build_info["builtAt"],
    "unsigned": True,
    "externalEnginesIncluded": False,
    "targetExecutionTested": False,
    "artifacts": [],
}
notices = [Path("LICENSE"), Path("README.md"), Path("README.tr.md"), Path("THIRD_PARTY.md"), Path("SECURITY.md")]
go_license = Path(subprocess.check_output(["go", "env", "GOROOT"], text=True).strip()) / "LICENSE"
documents = sorted(path for path in Path("docs").rglob("*") if path.is_file())
artifacts = []
for binary in sorted(binaries.iterdir()):
    if binary.name == "BUILD-INFO.json":
        continue
    match = re.fullmatch(r"accessweaver-([a-z]+)-([a-z0-9]+)(\.exe)?", binary.name)
    if not match:
        raise SystemExit(f"Unexpected binary: {binary.name}")
    target_os, target_arch, extension = match.groups()
    directory = f"accessweaver-{label}-{target_os}-{target_arch}"
    pairs = [(binary, f"{directory}/accessweaver{extension or ''}")]
    pairs += [(path, f"{directory}/{path.as_posix()}") for path in notices + documents]
    pairs += [(Path("internal/workflow/presets/LICENSE.SplitWire-Turkey"), f"{directory}/licenses/SplitWire-Turkey-MIT.txt")]
    pairs += [(go_license, f"{directory}/licenses/Go-runtime-LICENSE")]
    target_info = dict(build_info, platform=target_os, arch=target_arch)
    target_info_file = binaries.parent / (directory + "-BUILD-INFO.json")
    target_info_file.write_text(json.dumps(target_info, indent=2) + "\n", encoding="utf-8")
    pairs += [(target_info_file, f"{directory}/BUILD-INFO.json")]
    sbom_notices = binaries.parent / (directory + "-notices")
    sbom_file = binaries.parent / (directory + "-SBOM.cdx.json")
    bom = generate(binary, Path.cwd(), "./cmd/accessweaver", target_info, sbom_notices)
    sbom_file.write_text(json.dumps(bom, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    subprocess.run([str(binaries.parent / "sbom-schema"), "--schemas", str(Path("scripts/sbom/schema").resolve()), str(sbom_file)], check=True)
    pairs += [(sbom_file, f"{directory}/SBOM.cdx.json")]
    for notice in sorted(sbom_notices.iterdir()):
        name = f"{directory}/licenses/{notice.name}"
        existing = [source for source, target in pairs if target == name]
        if existing:
            if existing[0].read_bytes() != notice.read_bytes():
                raise SystemExit("Conflicting SBOM notice: " + notice.name)
        else:
            pairs.append((notice, name))
    archive = out / (directory + (".zip" if target_os == "windows" else ".tar.gz"))
    write_archive(archive, pairs, epoch, executable=f"{directory}/accessweaver{extension or ''}")
    checksum = hashlib.sha256(archive.read_bytes()).hexdigest()
    artifacts.append(archive)
    manifest["artifacts"].append({
        "file": archive.name, "goos": target_os, "goarch": target_arch,
        "sha256": checksum, "bytes": archive.stat().st_size,
    })

manifest_file = out / "BUILD-MANIFEST.json"
manifest_file.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
artifacts.append(manifest_file)
(out / "SHA256SUMS.txt").write_text("".join(
    f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in artifacts
), encoding="utf-8")
print(f"Packaged {len(manifest['artifacts'])} unsigned targets in {out}")
PY
