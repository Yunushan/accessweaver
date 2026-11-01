#!/usr/bin/env bash
# Native multi-user regression test for an isolated CI/disposable test session.
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Linux || "$(id -u)" == 0 ]]; then
  echo 'Run this test as a normal Linux user with sudo permission for nobody.' >&2
  exit 1
fi
binary="$(realpath "${1:-./accessweaver}")"
test_dir="$(mktemp -d /tmp/accessweaver-session-test.XXXXXXXX)"
chmod 755 "$test_dir"
cp scripts/test-linux-session.py "$test_dir/probe.py"
chmod 644 "$test_dir/probe.py"
server_pid=''
finish() {
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    for ((attempt=0; attempt<50; attempt++)); do
      if ! kill -0 "$server_pid" 2>/dev/null; then break; fi
      sleep 0.1
    done
    kill -KILL "$server_pid" 2>/dev/null || true
    wait "$server_pid" || true
  fi
  # Keep the bounded temporary test session for diagnosis, with its credential
  # file removed by normal application shutdown. Never clean unrelated state.
}
trap finish EXIT
ACCESSWEAVER_HOME="$test_dir/state" XDG_CACHE_HOME="$test_dir/cache" ACCESSWEAVER_NO_BROWSER=1 \
  "$binary" ui > "$test_dir/server.log" 2>&1 &
server_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  if grep -q '^Open this private launch file' "$test_dir/server.log"; then break; fi
  if ! kill -0 "$server_pid" 2>/dev/null; then cat "$test_dir/server.log" >&2; exit 1; fi
  sleep 0.1
done
python3 "$test_dir/probe.py" --mode owner --server-log "$test_dir/server.log"
sudo -n -u nobody python3 "$test_dir/probe.py" --mode foreign --server-log "$test_dir/server.log"
