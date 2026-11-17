#!/usr/bin/env bash
# Use the same packaging environment for both hosted builds.
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ $# != 4 || ( "$1" != package && "$1" != rebuild ) ]]; then
  echo 'Usage: package-hosted-release.sh package|rebuild LABEL SOURCE_COMMIT GO_VERSION' >&2
  exit 2
fi
mode="$1"
label="$2"
commit="$3"
version="$4"
test "$(git rev-parse HEAD)" = "$commit"
test -z "$(git status --porcelain)"

export GOTOOLCHAIN=local GOENV=off GOWORK=off GOFLAGS=
test "$(go version)" = "go version go$version linux/amd64"
sdk="$(go env GOROOT)"
state="$(mktemp -d "${RUNNER_TEMP:-/tmp}/accessweaver-portable.XXXXXXXX")"
trap 'GOMODCACHE="$state/go-mod" go clean -modcache; rm -rf -- "$state"' EXIT
mkdir "$state/go-mod" "$state/go-build" "$state/tmp"
export GOMODCACHE="$state/go-mod"

go mod download
go -C scripts/sbom-tools mod download

image=mcr.microsoft.com/playwright:v1.64.1-noble@sha256:2f05f8a734509a7b3f26a912639488ee08f58a7b292d14d62271bcff9038768f
docker run --rm --init --interactive --platform linux/amd64 --network none \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,source=$PWD,target=/workspace" \
  --mount "type=bind,source=$sdk,target=/aw-go,readonly" \
  --mount "type=bind,source=$state,target=/aw-state" \
  --workdir /workspace --entrypoint /bin/bash \
  --env PATH=/aw-go/bin:/usr/bin:/bin \
  --env GOCACHE=/aw-state/go-build --env GOMODCACHE=/aw-state/go-mod --env TMPDIR=/aw-state/tmp \
  --env GOTOOLCHAIN=local --env GOENV=off --env GOWORK=off --env GOFLAGS= \
  --env GOPROXY=off --env GOSUMDB=off --env GIT_CONFIG_GLOBAL=/dev/null --env GIT_CONFIG_SYSTEM=/dev/null \
  --env GIT_CONFIG_COUNT=1 --env GIT_CONFIG_KEY_0=safe.directory --env GIT_CONFIG_VALUE_0=/workspace \
  --env LC_ALL=C.UTF-8 --env TZ=UTC --env BUILD_VERSION --env SOURCE_DATE_EPOCH \
  "$image" -s -- "$mode" "$label" "$commit" "$version" <<'PACKAGE'
set -euo pipefail
umask 022
mode="$1"
label="$2"
test "$(git rev-parse HEAD)" = "$3"
test -z "$(git status --porcelain)"
test "$(go version)" = "go version go$4 linux/amd64"
go mod verify
go -C scripts/sbom-tools mod verify
printf 'Packaging runtime: '
python3 -c 'import platform, zlib; print(platform.python_version(), zlib.ZLIB_VERSION, zlib.ZLIB_RUNTIME_VERSION)'
verify_flags=(--check-go-metadata)
if [[ "$mode" == package ]]; then
  verify_flags+=(--execute-native --require-update-build)
fi
bash scripts/package-release.sh "$label"
python3 scripts/verify-release.py "dist/$label" "${verify_flags[@]}"
if [[ "$mode" == package ]]; then
  cp "dist/$label/SHA256SUMS.txt" /aw-state/first-package-checksums.txt
  bash scripts/package-release.sh "$label"
  python3 scripts/verify-release.py "dist/$label" "${verify_flags[@]}"
  cmp /aw-state/first-package-checksums.txt "dist/$label/SHA256SUMS.txt"
fi
PACKAGE
