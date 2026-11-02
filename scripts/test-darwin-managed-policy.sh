#!/usr/bin/env bash
# Native enrollment only on an explicitly opted-in, fresh GitHub-hosted Mac.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST:-}" != 1 || "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != macOS || "$(uname -s)" != Darwin || "$(id -u)" == 0 ]]; then
 echo 'Refusing machine changes outside an ordinary-user disposable hosted Mac job.' >&2
 exit 1
fi
policy=/Library/Preferences/AccessWeaver
coordination=/Library/Preferences/.accessweaver-policy.lock
if sudo -n test -e "$policy" || sudo -n test -L "$policy" || sudo -n test -e "$coordination" || sudo -n test -L "$coordination"; then
 echo 'Refusing preexisting native policy/coordination objects.' >&2
 exit 1
fi
shopt -s nullglob
existing=(/Library/Preferences/.accessweaver-policy-stage-*)
if ((${#existing[@]})); then
 echo 'Refusing preexisting reserved staging objects.' >&2
 exit 1
fi
mkdir -p build/managed-policy-checks
CGO_ENABLED=0 go test -c -o build/darwin-managed-policy.test ./cmd/accessweaver
CGO_ENABLED=0 go test -c -o build/darwin-policy-transactions.test ./internal/managed
sudo -n env ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST=1 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted RUNNER_OS=macOS GITHUB_SHA="${GITHUB_SHA:?}" "$PWD/build/darwin-managed-policy.test" -test.run='^TestDisposableDarwinManagedPolicyNative$' -test.v
sudo -n env ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST=1 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted RUNNER_OS=macOS GITHUB_SHA="${GITHUB_SHA:?}" "$PWD/build/darwin-policy-transactions.test" -test.run='^TestDisposableDarwinPolicyTransactions$' -test.v
if sudo -n test -e "$policy" || sudo -n test -L "$policy" || sudo -n test -e "$coordination" || sudo -n test -L "$coordination"; then
 echo 'Native policy fixture failed to remove its owned authority.' >&2
 exit 1
fi
remaining=(/Library/Preferences/.accessweaver-policy-stage-*)
if ((${#remaining[@]})); then
 echo 'Native policy fixture retained staging objects; inspection required.' >&2
 exit 1
fi
