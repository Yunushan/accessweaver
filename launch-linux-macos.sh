#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ -x "./accessweaver" ]; then
  exec ./accessweaver ui
fi
printf '%s\n' 'Missing ./accessweaver. Download the correct binary or build from source.' >&2
exit 1
