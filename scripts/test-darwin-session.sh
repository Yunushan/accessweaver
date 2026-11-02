#!/usr/bin/env bash
# Source-bound cross-user ACL regression on explicitly disposable hosted Macs.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${ACCESSWEAVER_DISPOSABLE_DARWIN_SESSION_TEST:-}" != 1 || "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != macOS || "$(uname -s)" != Darwin || "$(id -u)" == 0 ]]; then
  echo 'Refusing session ACL fixture outside an ordinary-user disposable hosted Mac.' >&2
  exit 1
fi
baseline_revision=84b4009dd0a603aec789191eb65823068cfa2dc6
if ! git cat-file -e "$baseline_revision^{commit}" 2>/dev/null; then
  git fetch --no-tags --depth=1 origin "$baseline_revision"
fi
baseline_dir="$(mktemp -d /private/tmp/accessweaver-session-baseline.XXXXXXXX)"
trap 'rm -f "$baseline_dir/launcher.go" "$baseline_dir/access_unix.go" "$baseline_dir/session_darwin_test.go" "$baseline_dir/go.mod"; rmdir "$baseline_dir"' EXIT
for source in launcher.go access_unix.go; do
  git show "$baseline_revision:internal/uiaccess/$source" > "$baseline_dir/$source"
done
cp internal/uiaccess/session_darwin_test.go "$baseline_dir/session_darwin_test.go"
printf 'module sessionbaseline\n\ngo 1.26.0\n' > "$baseline_dir/go.mod"
mkdir -p build/darwin-session-checks
report_dir="$PWD/build/darwin-session-checks"
(
  cd "$baseline_dir"
  CGO_ENABLED=0 GOTOOLCHAIN=local GITHUB_SHA="$baseline_revision" ACCESSWEAVER_EXPECT_DARWIN_SESSION_BASELINE_LEAK=1 ACCESSWEAVER_DARWIN_SESSION_REPORT="$report_dir/baseline.json" go test -run '^TestDisposableDarwinInheritedACLSession$' -count=1 -v
)
CGO_ENABLED=0 ACCESSWEAVER_EXPECT_DARWIN_SESSION_BASELINE_LEAK=0 ACCESSWEAVER_DARWIN_SESSION_REPORT="$report_dir/patched.json" go test ./internal/uiaccess -run '^TestDisposableDarwinInheritedACLSession$' -count=1 -v
