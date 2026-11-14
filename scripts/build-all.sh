#!/usr/bin/env bash
# Cross-compile the AccessWeaver core. This does not test target OS networking.
set -euo pipefail
cd "$(dirname "$0")/.."

# Resolve dependencies from this checkout and ignore per-user Go settings.
export GOENV=off GOWORK=off GOFLAGS=

command -v go >/dev/null 2>&1 || { echo "Go is required. Install it from https://go.dev/dl/" >&2; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "Python 3 is required for build metadata." >&2; exit 1; }
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

commit="unknown"
source_state="unknown"
stamp_vcs=false
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  commit="$(git rev-parse HEAD)"
  stamp_vcs=true
  source_state="clean"
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then source_state="modified"; fi
fi
# The source commit supplies a stable default; explicit epochs support independent
# rebuilds. Unknown source trees retain the current-time fallback.
epoch="${SOURCE_DATE_EPOCH-}"
if [[ -z ${SOURCE_DATE_EPOCH+x} ]]; then
  if [[ "$commit" != unknown ]]; then epoch="$(git show -s --format=%ct HEAD)";
  else epoch="$(date -u '+%s')"; fi
fi
build_time="$(python3 scripts/release_archive.py timestamp "$epoch")"
link_flags="-s -w -X github.com/Yunushan/accessweaver/internal/buildinfo.Commit=$commit -X github.com/Yunushan/accessweaver/internal/buildinfo.SourceState=$source_state -X github.com/Yunushan/accessweaver/internal/buildinfo.BuiltAt=$build_time"
if [[ -n "${BUILD_VERSION:-}" ]]; then
  if [[ ! "$BUILD_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.-]+)?(\+[a-zA-Z0-9.-]+)?$ ]]; then
    echo "BUILD_VERSION must be a semantic version." >&2; exit 1
  fi
  link_flags+=" -X github.com/Yunushan/accessweaver/internal/buildinfo.Version=$BUILD_VERSION"
fi
GOOS="$(go env GOHOSTOS)" GOARCH="$(go env GOHOSTARCH)" CGO_ENABLED=0 \
  go run -mod=readonly -buildvcs=false -ldflags="$link_flags" ./cmd/accessweaver version --json > "$output_dir/BUILD-INFO.json"

for target in "${targets[@]}"; do
  target_os="${target%/*}"
  target_arch="${target#*/}"
  extension=""
  if [[ "$target_os" == windows ]]; then extension=".exe"; fi
  echo "Building $target"
  GOOS="$target_os" GOARCH="$target_arch" CGO_ENABLED=0 \
    go build -mod=readonly -trimpath -buildvcs="$stamp_vcs" -ldflags="$link_flags" \
    -o "$output_dir/accessweaver-$target_os-$target_arch$extension" ./cmd/accessweaver
done

echo "Binaries written to $output_dir. No external engines are included."
