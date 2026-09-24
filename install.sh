#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: install.sh [--monitor boinc|process|docker[,...]]" >&2
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

# Canonicalize a comma-separated monitor list the way sentinel does: known
# names deduplicated in boinc,process,docker order. Unknown names fail.
normalize_monitor() {
    local part result="" name
    local -a parts
    local -A seen=()
    IFS=, read -r -a parts <<<"$1"
    for part in "${parts[@]}"; do
        [[ -n ${part} ]] || continue
        case "${part}" in
            boinc|process|docker) seen[${part}]=1 ;;
            *) echo "unknown monitor: ${part}" >&2; return 1 ;;
        esac
    done
    for name in boinc process docker; do
        [[ -n ${seen[${name}]:-} ]] && result+=${result:+,}${name}
    done
    printf '%s\n' "${result}"
}

has_monitor() {
    [[ ,${monitor}, == *,$1,* ]]
}

configured=$(conf_value SENTINEL_MONITOR)
if [[ -n ${configured} ]]; then
    configured=$(normalize_monitor "${configured}") || usage
fi
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
        echo "  3) Docker containers"
        echo "  4) BOINC and services/processes"
        read -r -p "choice [1]: " choice
        case "${choice:-1}" in
            1) monitor=boinc ;;
            2) monitor=process ;;
            3) monitor=docker ;;
            4) monitor=boinc,process ;;
            *) echo "invalid choice: ${choice}" >&2; exit 2 ;;
        esac
    else
        monitor=boinc
    fi
fi
monitor=$(normalize_monitor "$(tr -d ' \t' <<<"${monitor}" | tr '[:upper:]' '[:lower:]')") || usage
[[ -n ${monitor} ]] || usage
if [[ -n ${configured} && ${configured} != "${monitor}" ]]; then
    echo "${conf} sets SENTINEL_MONITOR=${configured}; refusing to switch to ${monitor}." >&2
    echo "Change SENTINEL_MONITOR there first if the switch is intended." >&2
    exit 1
fi

if has_monitor boinc; then
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
if has_monitor docker && [[ ! -S /var/run/docker.sock ]]; then
    echo "warning: /var/run/docker.sock not found; is Docker installed and running?" >&2
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

# Each option installs only its own drop-ins and removes the others, so a
# rerun after changing RECOVER_ENABLED also brings restart.conf in line.
# timer.d/process.conf is the name the 5 minute drop-in had in the first
# release with option 2.
rm -f "${service_dropins}/boinc.conf" "${service_dropins}/restart.conf" \
    "${service_dropins}/docker.conf" "${timer_dropins}/interval.conf" \
    "${timer_dropins}/process.conf"
if has_monitor boinc; then
    install -D -m 0644 "${source_dir}/systemd/sentinel.service.d/boinc.conf" \
        "${service_dropins}/boinc.conf"
fi
if has_monitor process || has_monitor docker; then
    # The 5 minute timer suits services and containers, but BOINC keeps its
    # 15 minutes when combined: a denser schedule is likelier to catch the
    # brief gap between two tasks as starvation and run the destructive sync.
    if ! has_monitor boinc; then
        install -D -m 0644 "${source_dir}/systemd/sentinel.timer.d/interval.conf" \
            "${timer_dropins}/interval.conf"
    fi
    if has_monitor docker; then
        install -D -m 0644 "${source_dir}/systemd/sentinel.service.d/docker.conf" \
            "${service_dropins}/docker.conf"
    fi
    if has_monitor process; then
        # systemctl restart needs CAP_SYS_ADMIN; grant it only while auto-recovery is on.
        case "$(conf_value RECOVER_ENABLED)" in
            0|false|no|off) ;;
            *)
                install -D -m 0644 "${source_dir}/systemd/sentinel.service.d/restart.conf" \
                    "${service_dropins}/restart.conf"
                ;;
        esac
        example=targets.example
        prompt="service <unit> | process <name> | cmdline <regex>"
        if has_monitor docker; then
            prompt="${prompt} | container <name>"
        fi
    else
        example=targets.docker.example
        prompt="container <name>"
    fi

    if [[ ! -e ${targets} ]]; then
        install -m 0600 "${source_dir}/config/${example}" "${targets}"
        if [[ -t 0 ]]; then
            echo "Register targets, one per line: ${prompt}"
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

if [[ ${monitor} != boinc ]]; then
    # sentinel reads sentinel.conf itself when started from a shell.
    if ! /usr/local/sbin/sentinel check-config; then
        echo "check-config failed. Fix ${targets}, then rerun install.sh" >&2
        echo "or check with: sudo /usr/local/sbin/sentinel check-config" >&2
        exit 1
    fi
fi

systemctl enable --now sentinel.timer

echo "Sentinel installed (monitor=${monitor}). Configure ${conf}"
echo "and /etc/sentinel/telegram-token, then run:"
echo "  systemctl start sentinel.service"
