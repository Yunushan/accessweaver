#!/bin/sh
# Runs only inside the disposable official guest, after nuageinit runcmd.
# Observe startup without starting/restarting services or exporting raw output.
set -eu
[ "${ACCESSWEAVER_DISPOSABLE_BSD_BOOT_OBSERVER:-}" = "1" ] || exit 1
[ "$(/usr/bin/uname -s)" = "FreeBSD" ] || exit 1
[ "$(/usr/bin/id -u)" = "0" ] || exit 1
umask 077
configuration=false
if /usr/sbin/sshd -t >/dev/null 2>/var/log/accessweaver-sshd-configtest.log; then
    configuration=true
    configuration_exit=0
else
    configuration_exit=$?
fi
configuration_log_bytes=$(/usr/bin/wc -c </var/log/accessweaver-sshd-configtest.log)
running=false
attempt=0
while [ "$attempt" -lt 60 ]; do
    if /usr/sbin/service sshd onestatus >/dev/null 2>&1; then
        running=true
        break
    fi
    attempt=$((attempt + 1))
    /bin/sleep 1
done
address=false
if /sbin/ifconfig vtnet0 inet 2>/dev/null | /usr/bin/grep -Eq 'inet 10[.]0[.]2[.]15([[:space:]]|$)'; then
    address=true
fi
listening=false
if /usr/bin/sockstat -4l -P tcp 2>/dev/null | /usr/bin/awk '$2 == "sshd" && $5 == "tcp4" && $6 ~ /:22$/ { seen=1 } END { exit !seen }'; then
    listening=true
fi
printf '{"configurationValid":%s,"configurationExitCode":%s,"configurationLogBytes":%s,"serviceRunning":%s,"controlAddressConfigured":%s,"ipv4SSHListening":%s}\n' \
    "$configuration" "$configuration_exit" "$configuration_log_bytes" "$running" "$address" "$listening" >/root/.accessweaver-boot-state.tmp
/bin/mv /root/.accessweaver-boot-state.tmp /root/accessweaver-boot-state.json
