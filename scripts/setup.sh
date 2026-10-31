#!/usr/bin/env bash
# Build from this source checkout into ./bin; no system installation.
set -euo pipefail
cd "$(dirname "$0")/.."
case "${1:-}" in
  ""|--run) ;;
  -h|--help) echo "Usage: bash scripts/setup.sh [--run]"; exit 0 ;;
  *) echo "Usage: bash scripts/setup.sh [--run]" >&2; exit 1 ;;
esac
command -v go >/dev/null 2>&1 || { echo "Install Go from https://go.dev/dl/ and rerun this script." >&2; exit 1; }
mkdir -p bin
go build -trimpath -o bin/accessweaver ./cmd/accessweaver
echo "Built bin/accessweaver. Start the dashboard with: ./bin/accessweaver ui"
if [[ "${1:-}" == --run ]]; then exec ./bin/accessweaver ui; fi
