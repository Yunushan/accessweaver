#!/usr/bin/env bash
# Build unsigned, self-contained core archives with notices and checksums.
set -euo pipefail
cd "$(dirname "$0")/.."

release_label="${1:-preview}"
if [[ ! "$release_label" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
  echo "Release label may contain letters, digits, dots, underscores and hyphens." >&2
  exit 1
fi
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required for packaging." >&2; exit 1; }

# Build in a fresh private temporary directory, so old files never enter a release.
stage_dir="$(mktemp -d "${TMPDIR:-/tmp}/accessweaver-release.XXXXXXXX")"
trap 'rm -rf "$stage_dir"' EXIT
OUTPUT_DIR="$stage_dir/bin" bash scripts/build-all.sh

python3 - "$release_label" "$stage_dir/bin" <<'PY'
from pathlib import Path
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import zipfile

label, binaries = sys.argv[1], Path(sys.argv[2])
out = Path("dist") / label
out.mkdir(parents=True, exist_ok=True)
manifest = {
    "project": "AccessWeaver",
    "releaseLabel": label,
    "goVersion": subprocess.check_output(["go", "version"], text=True).strip(),
    "sourceCommit": "unknown",
    "unsigned": True,
    "externalEnginesIncluded": False,
    "targetExecutionTested": False,
    "artifacts": [],
}
try:
    manifest["sourceCommit"] = subprocess.check_output(
        ["git", "rev-parse", "HEAD"], text=True, stderr=subprocess.DEVNULL
    ).strip()
except (OSError, subprocess.CalledProcessError):
    pass

notices = [Path("LICENSE"), Path("README.md"), Path("README.tr.md"), Path("THIRD_PARTY.md"), Path("SECURITY.md")]
documents = sorted(path for path in Path("docs").rglob("*") if path.is_file())
artifacts = []
for binary in sorted(binaries.iterdir()):
    match = re.fullmatch(r"accessweaver-([a-z]+)-([a-z0-9]+)(\.exe)?", binary.name)
    if not match:
        raise SystemExit(f"Unexpected binary: {binary.name}")
    target_os, target_arch, extension = match.groups()
    directory = f"accessweaver-{label}-{target_os}-{target_arch}"
    pairs = [(binary, f"{directory}/accessweaver{extension or ''}")]
    pairs += [(path, f"{directory}/{path.as_posix()}") for path in notices + documents]
    archive = out / (directory + (".zip" if target_os == "windows" else ".tar.gz"))
    if target_os == "windows":
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
            for source, name in pairs:
                zipped.write(source, name)
    else:
        with tarfile.open(archive, "w:gz") as tar:
            for source, name in pairs:
                tar.add(source, arcname=name, recursive=False)
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
