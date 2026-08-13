#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

install -D -m 0755 "${source_dir}/src/sentinel.py" /usr/local/sbin/sentinel
install -D -m 0644 "${source_dir}/systemd/sentinel.service" /etc/systemd/system/sentinel.service
install -D -m 0644 "${source_dir}/systemd/sentinel.timer" /etc/systemd/system/sentinel.timer
install -D -m 0644 "${source_dir}/README.md" /usr/local/share/doc/sentinel/README.md
install -d -m 0700 /etc/sentinel
chown root:root /etc/sentinel
chmod 0700 /etc/sentinel

if [[ ! -e /etc/sentinel/sentinel.conf ]]; then
    install -m 0600 "${source_dir}/config/sentinel.conf.example" /etc/sentinel/sentinel.conf
fi
if [[ ! -e /etc/sentinel/telegram-token ]]; then
    install -m 0600 /dev/null /etc/sentinel/telegram-token
fi
chown root:root /etc/sentinel/sentinel.conf /etc/sentinel/telegram-token
chmod 0600 /etc/sentinel/sentinel.conf /etc/sentinel/telegram-token

# The BOINC unit may have NeedDaemonReload=yes. Reload unit definitions without
# restarting BOINC, then enable only the Sentinel timer.
systemctl daemon-reload
systemctl enable --now sentinel.timer

echo "Sentinel installed. Configure /etc/sentinel/sentinel.conf"
echo "and /etc/sentinel/telegram-token, then run:"
echo "  systemctl start sentinel.service"
