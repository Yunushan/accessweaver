#!/bin/sh
# Experimental clean-install-only package: preserve any existing app/receipt.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH
LC_ALL=C; export LC_ALL
[ "$(/usr/bin/id -u)" -eq 0 ] || exit 1
[ "${3:-}" = / ] || exit 1
if [ -e /Applications/AccessWeaver.app ] || [ -L /Applications/AccessWeaver.app ]; then
    echo 'AccessWeaver experimental package refuses an existing app.' >&2
    exit 1
fi
# A partial/corrupt receipt may not be recognized by pkgutil. Its bytes and
# aliases are still existing state, and must not be overwritten by this package.
for receipt in /private/var/db/receipts/io.github.yunushan.accessweaver.plist /private/var/db/receipts/io.github.yunushan.accessweaver.bom; do
    if [ -e "$receipt" ] || [ -L "$receipt" ]; then
        echo 'AccessWeaver experimental package refuses existing receipt state.' >&2
        exit 1
    fi
done
if /usr/sbin/pkgutil --pkg-info io.github.yunushan.accessweaver >/dev/null 2>&1; then
    echo 'AccessWeaver experimental package refuses an existing receipt.' >&2
    exit 1
fi
exit 0
