#!/usr/bin/env bash
# Cross-compile the AccessWeaver core. This does not test target OS networking.
set -euo pipefail
cd "$(dirname "$0")/.."

command -v go >/dev/null 2>&1 || { echo "Go is required. Install it from https://go.dev/dl/" >&2; exit 1; }
output_dir="${OUTPUT_DIR:-dist}"
mkdir -p "$output_dir"
targets=(linux/amd64 linux/arm64 windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 freebsd/amd64 freebsd/arm64 openbsd/amd64 openbsd/arm64)
if (($#)); then targets=("$@"); fi

for target in "${targets[@]}"; do
  case "$target" in
    linux/amd64|linux/arm64|windows/amd64|windows/arm64|darwin/amd64|darwin/arm64|freebsd/amd64|freebsd/arm64|openbsd/amd64|openbsd/arm64) ;;
    *) echo "Unsupported build target: $target" >&2; exit 1 ;;
  esac
done

for target in "${targets[@]}"; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  extension=""
  if [[ "$target_os" == windows ]]; then extension=".exe"; fi
  echo "Building $target"
  GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
    go build -trimpath -buildvcs=false -ldflags='-s -w' \
    -o "$output_dir/accessweaver-$target_os-$target_arch$extension" ./cmd/accessweaver
done

echo "Binaries written to $output_dir. No external engines are included."
