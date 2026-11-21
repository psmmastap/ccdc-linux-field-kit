#!/bin/sh
# Install/remove auditd beacon-logging rules (checklist: heartbeat + exec tracking).
# Post-noon hunting phase, with root and official tool approval.
# Rules are written to their own file with clear markers and removed cleanly.
# Usage: sudo sh beacon_logging.sh --install | --remove | --status
set -u
umask 077
PATH=${PATH:-/usr/bin:/bin}:/usr/sbin:/sbin
export PATH

RULES_FILE=/etc/audit/rules.d/50-ccdc-beacon.rules
MARKER='# CCDC-BEACON-RULES (added by ccdc field kit; safe to delete whole file)'

usage() {
    printf '%s\n' 'Usage: sudo sh beacon_logging.sh --install | --remove | --status' \
      '' \
      '--install  Write connect/accept + execve audit rules (IPv4+IPv6, 64+32 bit),' \
      '           load them (augenrules, fallback: restart auditd), verify, then' \
      '           print the ausearch/aureport commands for investigating.' \
      '--remove   Delete the rules file and reload (clean teardown).' \
      '--status   Show whether the rules are currently loaded.' \
      '' \
      'Requires auditd. If auditd is absent, the script explains the iptables LOG' \
      'fallback instead of half-configuring anything.'
    exit 2
}

have() { command -v "$1" >/dev/null 2>&1; }

auditd_ready() {
    have auditctl || return 1
    [ -d /etc/audit/rules.d ] || return 1
    return 0
}

install_rules() {
    if ! auditd_ready; then
        printf '%s\n' 'auditd/auditctl not usable here. Manual fallback (iptables LOG):' \
          '  iptables -I OUTPUT 1 -m state --state NEW -p tcp -j LOG --log-prefix "BEACON_HUNT: "' \
          '  tail -f /var/log/syslog | grep BEACON_HUNT    # Debian' \
          '  tail -f /var/log/messages | grep BEACON_HUNT  # RHEL' \
          '' \
          'Install policy first: apt install auditd audispd-plugins / dnf install audit'
        exit 1
    fi
    cat > "$RULES_FILE" <<'EOF'
# CCDC-BEACON-RULES (added by ccdc field kit; safe to delete whole file)
# Heartbeat: outbound/new network connections
-a always,exit -F arch=b64 -S connect,accept -k beacon_network
-a always,exit -F arch=b32 -S connect,accept -k beacon_network
# Payload: process execution
-a always,exit -F arch=b64 -S execve -k beacon_exec
-a always,exit -F arch=b32 -S execve -k beacon_exec
EOF
    chmod 600 "$RULES_FILE"
    if have augenrules; then
        augenrules --load >/dev/null 2>&1 || service auditd restart >/dev/null 2>&1
    else
        service auditd restart >/dev/null 2>&1
    fi
    if auditctl -l 2>/dev/null | grep -q beacon_network; then
        printf '%s\n' 'INSTALLED AND LOADED. Investigate with:' \
          '  ausearch -k beacon_network -i --format text     # full events, no context loss' \
          '  ausearch -k beacon_network -i | grep saddr=     # remote IPs' \
          '  ausearch -k beacon_network --address 1.2.3.4 -i # trace ONE C2 IP (fast)' \
          '  ausearch -k beacon_exec -i | grep -E "exe=|proctitle="' \
          '  aureport -x --summary -i                       # exec summary (needs execve rules)' \
          '' \
          'CAUTION: execve rules are noisy on busy boxes; remove the exec lines and' \
          'rerun --install if the box slows down or logs fill the disk.'
    else
        printf '%s\n' 'rules written but NOT visible via auditctl -l. Check: service auditd status,' \
          'disk space (df -h /var/log/audit), and reboot-to-load if ausearch stays empty.'
        exit 1
    fi
}

remove_rules() {
    if [ -f "$RULES_FILE" ]; then
        rm -f "$RULES_FILE" || exit 1
        have augenrules && augenrules --load >/dev/null 2>&1
        printf '%s\n' "removed $RULES_FILE and reloaded audit rules"
    else
        printf '%s\n' "no rules file present ($RULES_FILE)"
    fi
}

status_rules() {
    if auditctl -l 2>/dev/null | grep -q beacon; then
        printf '%s\n' 'beacon rules ACTIVE:' && auditctl -l | grep beacon
    else
        printf '%s\n' "beacon rules not loaded (file present: $([ -f "$RULES_FILE" ] && echo yes || echo no))"
    fi
}

case "${1:-}" in
    --install) install_rules ;;
    --remove) remove_rules ;;
    --status) status_rules ;;
    *) usage ;;
esac
