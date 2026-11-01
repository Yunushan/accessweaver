#!/usr/bin/env bash
# Opt-in native policy tests on a fresh GitHub-hosted Linux VM only.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "${ACCESSWEAVER_DISPOSABLE_LINUX_POLICY_TEST:-}" != 1 || "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted || "${RUNNER_OS:-}" != Linux || "$(id -u)" == 0 ]]; then
  echo 'Refusing machine policy tests outside a disposable hosted Linux job.' >&2
  exit 1
fi
if sudo -n test -e /etc/accessweaver || sudo -n test -L /etc/accessweaver || sudo -n test -e /etc/.accessweaver-policy.lock || sudo -n test -L /etc/.accessweaver-policy.lock; then
  echo 'Refusing to replace preexisting machine policy.' >&2
  exit 1
fi
shopt -s nullglob
existing_stages=(/etc/.accessweaver-install-*)
if ((${#existing_stages[@]})); then
  echo 'Refusing preexisting bootstrap stages.' >&2
  exit 1
fi
mkdir -p build/managed-policy-checks
CGO_ENABLED=0 go test -c -o build/linux-managed-policy.test ./cmd/accessweaver
CGO_ENABLED=0 go test -c -o build/linux-policy-transactions.test ./internal/managed
run_native() {
  sudo -n env ACCESSWEAVER_DISPOSABLE_LINUX_POLICY_TEST=1 GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted RUNNER_OS=Linux GITHUB_SHA="${GITHUB_SHA:?}" "$@"
}
run_native "$PWD/build/linux-managed-policy.test" -test.run='^TestDisposableLinuxManagedPolicyNative$' -test.v
run_native "$PWD/build/linux-policy-transactions.test" -test.run='^TestDisposableLinuxPolicyTransactions$' -test.v
if sudo -n test -e /etc/accessweaver || sudo -n test -L /etc/accessweaver || sudo -n test -e /etc/.accessweaver-policy.lock || sudo -n test -L /etc/.accessweaver-policy.lock; then
  echo 'Native policy test did not remove its source.' >&2
  exit 1
fi

remaining_stages=(/etc/.accessweaver-install-*)
if ((${#remaining_stages[@]})); then
  echo 'Native policy tests retained bootstrap stages.' >&2
  exit 1
fi
