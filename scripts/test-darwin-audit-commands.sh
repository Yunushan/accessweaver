#!/usr/bin/env bash
# Source-Go ordinary command acceptance, only on an explicitly disposable Mac.
set -euo pipefail
cd "$(dirname "$0")/.."
fail() { printf '%s\n' 'Ordinary Darwin audit source fixture refused.' >&2; exit 1; }
[[ "${ACCESSWEAVER_DISPOSABLE_DARWIN_AUDIT_COMMANDS_TEST:-}" == 1 && "${ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST:-}" == 1 && "${GITHUB_ACTIONS:-}" == true && "${RUNNER_ENVIRONMENT:-}" == github-hosted && "${RUNNER_OS:-}" == macOS && "$(uname -s)" == Darwin && "$(id -u)" != 0 && "${GOTOOLCHAIN:-}" == local ]] || fail
source_commit=$(git rev-parse HEAD 2>/dev/null) || fail
[[ "$source_commit" =~ ^[0-9a-f]{40}$ && "$source_commit" == "${GITHUB_SHA:-}" && -z "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]] || fail
[[ "$(go env GOHOSTOS 2>/dev/null)" == darwin && "$(go version 2>/dev/null)" == "go version go${GO_VERSION:-} darwin/"* ]] || fail
sdk_arch=$(go env GOHOSTARCH 2>/dev/null)
case "$sdk_arch:${RUNNER_ARCH:-}:$(uname -m)" in amd64:X64:x86_64|arm64:ARM64:arm64) ;; *) fail ;; esac
policy=/Library/Preferences/AccessWeaver
coordination=/Library/Preferences/.accessweaver-policy.lock
if sudo -n test -e "$policy" 2>/dev/null || sudo -n test -L "$policy" 2>/dev/null || sudo -n test -e "$coordination" 2>/dev/null || sudo -n test -L "$coordination" 2>/dev/null; then fail; fi
shopt -s nullglob
reserved=(/Library/Preferences/.accessweaver-policy-stage-*)
((${#reserved[@]} == 0)) || fail
mkdir -p build >/dev/null 2>&1 || fail
CGO_ENABLED=0 go test -trimpath -c -ldflags "-X github.com/Yunushan/accessweaver/internal/buildinfo.Commit=$source_commit -X github.com/Yunushan/accessweaver/internal/buildinfo.SourceState=clean" -o build/darwin-audit-commands.test ./cmd/accessweaver >/dev/null 2>&1 || fail
[[ "$(git rev-parse HEAD 2>/dev/null)" == "$source_commit" && -z "$(git status --porcelain --untracked-files=normal 2>/dev/null)" ]] || fail
# Discard raw subprocess output in memory. Only source-fixed labels are emitted;
# there is no private report/log file, artifact upload or payload collection.
python3 - "$source_commit" "$sdk_arch" <<'PY'
import os, subprocess, sys
source, arch = sys.argv[1:]
labels = {
    'ordinary Darwin audit hosted source context unavailable',
    'ordinary Darwin audit source identity unavailable',
    'ordinary Darwin audit protected fixture setup failed',
    'ordinary Darwin audit exact fixture cleanup failed',
    'ordinary Darwin audit command worker failed',
    'ordinary Darwin audit worker identity unavailable',
    'ordinary Darwin audit worker home binding unavailable',
    'ordinary Darwin audit worker image binding unavailable',
    'ordinary Darwin audit worker public backend unavailable',
    'ordinary Darwin audit worker lifecycle binding unavailable',
    'ordinary Darwin audit worker protocol unavailable',
}
cases = (
    'signed-required-audit-admission','initialize-import-retained-head',
    'audited-private-http-desktop','read-only-export-verify',
    'current-recorded-export-key-boundary','actual-output-alias-admission',
    'full-journal-reservation-refusal','approved-recorded-foreground-run',
    'recorded-foreground-output-cancellation-drain','private-command-workspace-cleanup',
)
for stage in ('host-context','source-binding','protected-ancestry','protected-source-staging','private-home','policy-preflight','required-policy-install','required-policy-bindings','worker-launch','worker-ipc','signal-lifetime-gate','worker-drain','owned-cleanup','unknown-bootstrap'):
    labels.add('ordinary Darwin audit bootstrap failed: '+stage)
for name in cases:
    labels.add('ordinary Darwin audit command case failed: '+name)
    labels.add('ordinary Darwin audit command case not executed: '+name)
command = ['/usr/bin/sudo','-n','/usr/bin/env','-i','PATH=/usr/bin:/bin:/usr/sbin:/sbin',
    'LANG=C','LC_ALL=C','TZ=UTC','GOTOOLCHAIN=local','GITHUB_ACTIONS=true',
    'RUNNER_ENVIRONMENT=github-hosted','RUNNER_OS=macOS',
    'RUNNER_ARCH='+os.environ['RUNNER_ARCH'],'GITHUB_SHA='+source,
    'GO_VERSION='+os.environ['GO_VERSION'],
    'ACCESSWEAVER_DISPOSABLE_DARWIN_POLICY_TEST=1',
    'ACCESSWEAVER_DISPOSABLE_DARWIN_AUDIT_COMMANDS_TEST=1',
    os.path.abspath('build/darwin-audit-commands.test'),
    '-test.run=^TestDisposableDarwinAuditCommands$', '-test.timeout=180s', '-test.v']
process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
seen, line, overflow, total = set(), bytearray(), False, 0
while True:
    block=process.stdout.read(4096)
    if not block: break
    total += len(block)
    if total > 1 << 20: overflow=True
    for value in block:
        if value == 10:
            text=line.decode('utf-8',errors='replace')
            if not overflow:
                for label in labels:
                    if text.endswith(label): seen.add(label)
            line.clear()
        elif len(line)<1024: line.append(value)
        else: overflow=True
process.stdout.close()
status=process.wait()
for label in sorted(seen): print(label)
passed=status==0 and not overflow and not seen
print('Ordinary Darwin audit source commands '+('PASS' if passed else 'FAIL'))
sys.exit(0 if passed else 1)
PY
if sudo -n test -e "$policy" 2>/dev/null || sudo -n test -L "$policy" 2>/dev/null || sudo -n test -e "$coordination" 2>/dev/null || sudo -n test -L "$coordination" 2>/dev/null; then fail; fi
reserved=(/Library/Preferences/.accessweaver-policy-stage-*)
((${#reserved[@]} == 0)) || fail
