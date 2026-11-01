#!/usr/bin/env bash
# Check every core release target plus both supported fixture build environments.
set -euo pipefail
cd "$(dirname "$0")/.."
project_root="$PWD"
output_dir="${1:-build/security-checks}"
mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
scanner="${GOVULNCHECK:-govulncheck}"
scanner_version="$(go -C scripts/security-tools list -m -f '{{.Version}}' golang.org/x/vuln)"
go_version="$(go env GOVERSION)"
"$scanner" -version > "$output_dir/tool-version.txt"

scan() {
  local scope="$1" target_os="$2" target_arch="$3" module_dir="$4" module_path="$5"
  local label="$scope-$target_os-$target_arch"
  (
    cd "$project_root/$module_dir"
    GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
      "$scanner" -db https://vuln.go.dev -json ./... > "$output_dir/$label.json" \
      2> "$output_dir/$label.stderr"
  ) || { cat "$output_dir/$label.stderr" >&2; return 1; }
  python3 "$project_root/scripts/check-vulnerability-report.py" "$output_dir/$label.json" \
    --module "$module_path" --target "$target_os/$target_arch" --scanner-version "$scanner_version" --go-version "$go_version" \
    --summary "$output_dir/$label-summary.json"
}

for target in linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/arm64 openbsd/amd64 openbsd/arm64; do
  scan core "${target%/*}" "${target#*/}" . github.com/Yunushan/accessweaver
done
for target in linux/amd64 windows/amd64; do
  scan fixture "${target%/*}" "${target#*/}" scripts/fixtures/wgpeer accessweaver.test/wgpeer
done
