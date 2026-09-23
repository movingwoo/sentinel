#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: install.sh [--monitor boinc|process]" >&2
    exit 2
}

if [[ ${EUID} -ne 0 ]]; then
    echo "install.sh must run as root" >&2
    exit 1
fi

monitor=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --monitor)
            [[ $# -ge 2 ]] || usage
            monitor=$2
            shift 2
            ;;
        --monitor=*)
            monitor=${1#*=}
            shift
            ;;
        *)
            usage
            ;;
    esac
done

source_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
conf=/etc/sentinel/sentinel.conf
targets=/etc/sentinel/targets
service_dropins=/etc/systemd/system/sentinel.service.d
timer_dropins=/etc/systemd/system/sentinel.timer.d

# Print the last value assigned to a key in sentinel.conf, lowercased and unquoted.
conf_value() {
    [[ -e ${conf} ]] || return 0
    sed -n "s/^[[:space:]]*$1[[:space:]]*=[[:space:]]*//p" "${conf}" \
        | tail -n 1 | tr -d "\"' \t\r" | tr '[:upper:]' '[:lower:]'
}

configured=$(conf_value SENTINEL_MONITOR)
if [[ -z ${monitor} ]]; then
    if [[ -n ${configured} ]]; then
        monitor=${configured}
    elif [[ -e ${conf} ]]; then
        # A sentinel.conf without SENTINEL_MONITOR predates the options: BOINC.
        monitor=boinc
    elif [[ -t 0 ]]; then
        echo "Select what this Sentinel watches:"
        echo "  1) BOINC"
        echo "  2) services/processes"
        read -r -p "choice [1]: " choice
        case "${choice:-1}" in
            1) monitor=boinc ;;
            2) monitor=process ;;
            *) echo "invalid choice: ${choice}" >&2; exit 2 ;;
        esac
    else
        monitor=boinc
    fi
fi
case "${monitor}" in
    boinc|process) ;;
    *) echo "unknown monitor: ${monitor}" >&2; usage ;;
esac
if [[ -n ${configured} && ${configured} != "${monitor}" ]]; then
    echo "${conf} sets SENTINEL_MONITOR=${configured}; refusing to switch to ${monitor}." >&2
    echo "Change SENTINEL_MONITOR there first if the switch is intended." >&2
    exit 1
fi

if [[ ${monitor} == boinc ]]; then
    # The BOINC drop-in adds SupplementaryGroups=boinc, which fails the unit
    # outright (216/GROUP) when the group does not exist.
    if ! getent group boinc >/dev/null; then
        echo "group 'boinc' is missing; install BOINC first or use --monitor process" >&2
        exit 1
    fi
    [[ -x /usr/bin/boinccmd ]] || echo "warning: /usr/bin/boinccmd not found" >&2
    systemctl cat boinc-client.service >/dev/null 2>&1 \
        || echo "warning: boinc-client.service not found" >&2
fi

install -D -m 0755 "${source_dir}/src/sentinel.py" /usr/local/sbin/sentinel
install -D -m 0644 "${source_dir}/systemd/sentinel.service" /etc/systemd/system/sentinel.service
install -D -m 0644 "${source_dir}/systemd/sentinel.timer" /etc/systemd/system/sentinel.timer
install -D -m 0644 "${source_dir}/README.md" /usr/local/share/doc/sentinel/README.md
install -d -m 0700 /etc/sentinel
chown root:root /etc/sentinel
chmod 0700 /etc/sentinel

if [[ ! -e ${conf} ]]; then
    install -m 0600 "${source_dir}/config/sentinel.conf.example" "${conf}"
fi
if [[ -z ${configured} ]]; then
    printf '\nSENTINEL_MONITOR=%s\n' "${monitor}" >>"${conf}"
fi
if [[ ! -e /etc/sentinel/telegram-token ]]; then
    install -m 0600 /dev/null /etc/sentinel/telegram-token
fi
chown root:root "${conf}" /etc/sentinel/telegram-token
chmod 0600 "${conf}" /etc/sentinel/telegram-token

if [[ ${monitor} == boinc ]]; then
    install -D -m 0644 "${source_dir}/systemd/sentinel.service.d/boinc.conf" \
        "${service_dropins}/boinc.conf"
    rm -f "${service_dropins}/restart.conf" "${timer_dropins}/process.conf"
else
    rm -f "${service_dropins}/boinc.conf"
    install -D -m 0644 "${source_dir}/systemd/sentinel.timer.d/process.conf" \
        "${timer_dropins}/process.conf"
    # systemctl restart needs CAP_SYS_ADMIN; grant it only while auto-recovery is on.
    case "$(conf_value RECOVER_ENABLED)" in
        0|false|no|off)
            rm -f "${service_dropins}/restart.conf"
            ;;
        *)
            install -D -m 0644 "${source_dir}/systemd/sentinel.service.d/restart.conf" \
                "${service_dropins}/restart.conf"
            ;;
    esac

    if [[ ! -e ${targets} ]]; then
        install -m 0600 "${source_dir}/config/targets.example" "${targets}"
        if [[ -t 0 ]]; then
            echo "Register targets, one per line: service <unit> | process <name> | cmdline <regex>"
            echo "Finish with an empty line."
            while IFS= read -r -p "> " line && [[ -n ${line} ]]; do
                printf '%s\n' "${line}" >>"${targets}"
            done
        fi
    fi
    chown root:root "${targets}"
    chmod 0600 "${targets}"
fi

# The BOINC unit may have NeedDaemonReload=yes. Reload unit definitions without
# restarting BOINC, then enable only the Sentinel timer.
systemctl daemon-reload

if [[ ${monitor} == process ]]; then
    if ! (set -a; . "${conf}"; set +a; /usr/local/sbin/sentinel check-config); then
        echo "check-config failed. Fix ${targets}, then rerun install.sh" >&2
        echo "or check with: sudo /usr/local/sbin/sentinel check-config" >&2
        exit 1
    fi
fi

systemctl enable --now sentinel.timer

echo "Sentinel installed (monitor=${monitor}). Configure ${conf}"
echo "and /etc/sentinel/telegram-token, then run:"
echo "  systemctl start sentinel.service"
