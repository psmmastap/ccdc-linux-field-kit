#!/usr/bin/env bash
# SERVICE menu - MORNING PHASE ONLY (fix and maintain services + injects).
# Threat hunting / implant removal before 12:00 = DISQUALIFICATION. Use threat/menu.sh after noon.
set -u
KIT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -f "$KIT_ROOT/config/team.conf" ] && . "$KIT_ROOT/config/team.conf"
EVIDENCE="${EVIDENCE_DIR:-/root/evidence}"
BACKUPS="${BACKUP_DIR:-/root/backups}"
WHITELIST="$KIT_ROOT/config/whitelist.txt"
SUDO=""
[ "$(id -u)" = 0 ] || SUDO="sudo"

banner() {
    clear 2>/dev/null || true
    cat <<'EOF'
=== SERVICE MENU - morning phase ===
Allowed now: fix services, backups, accounts, passwords, firewall, injects.
NOT allowed: threat hunting, implant removal (post-noon only; early = DQ).
Untouchable: whiteteam account + day's whitelisted processes/IPs (config/whitelist.txt).
EOF
}

pause() { printf '\n[enter to return to menu] '; read -r _; }

run_map()      { $SUDO python3 "$KIT_ROOT/service/map_environment.py" --output "$EVIDENCE"; }
run_netmap()   { printf 'Authorized targets (IP or CIDR, space-separated): '; read -r t_in
                 printf 'Scope (CIDR that contains them): '; read -r s_in
                 [ -n "$t_in" ] && [ -n "$s_in" ] || { echo "both a target list and a scope are required"; return 1; }
                 python3 "$KIT_ROOT/service/map_network.py" --authorized --target $t_in --scope $s_in --output "$EVIDENCE"; }
run_backup()   { printf 'Paths to back up (default: /etc /var/www /opt): '; read -r input
                 paths=(${input:-/etc /var/www /opt}); $SUDO python3 "$KIT_ROOT/service/backups.py" --paths "${paths[@]}" --output "$BACKUPS"
                 printf 'NOW ALSO: mysqldump/pg_dumpall (see FIELD-GUIDE.md). Check exit codes.\n'; }
run_genwatch() { python3 "$KIT_ROOT/service/gen_services.py" --output "$KIT_ROOT/config/services.local.json"; }
run_watch()    { printf 'Iterations (default 60) and interval seconds (default 30): '; read -r n i
                 python3 "$KIT_ROOT/service/check_services.py" --config "$KIT_ROOT/config/services.local.json" \
                   --count "${n:-60}" --interval "${i:-30}" --output "$EVIDENCE"; }
run_accounts() { $SUDO python3 "$KIT_ROOT/service/audit_accounts.py" --output "$EVIDENCE"; }
run_passwd()   { $SUDO python3 "$KIT_ROOT/service/rotate_passwords.py" --whitelist "$WHITELIST"; }
run_dbs()      { $SUDO python3 "$KIT_ROOT/service/db_audit.py" --output "$EVIDENCE"; }
run_docker()   { $SUDO python3 "$KIT_ROOT/service/docker_triage.py" --output "$EVIDENCE"; }
run_fwgen()    { printf 'Firewall config JSON (default config/firewall.example.json - EDIT FIRST): '; read -r cfg
                 python3 "$KIT_ROOT/service/firewall_rules.py" --config "${cfg:-$KIT_ROOT/config/firewall.example.json}" --output "$EVIDENCE"; }
run_fwapply()  { printf 'Candidate rules file (from firewall_rules.py, e.g. .../firewall-*/ipv4.rules): '; read -r r4
                 extra=""; [ -n "$r4" ] && extra="--rules4 $r4"
                 printf 'Rollback minutes (default 5): '; read -r mins
                 # shellcheck disable=SC2086
                 $SUDO python3 "$KIT_ROOT/service/firewall_apply.py" $extra --whitelist "$WHITELIST" --rollback-minutes "${mins:-5}"; }
run_log()      { printf 'What did you do: '; read -r text; sh "$KIT_ROOT/service/changelog.sh" "$text"; }
run_ready()    { sh "$KIT_ROOT/prepare_box.sh" --profile core,network,backup,triage,firewall --plan; }

while true; do
    banner
    cat <<EOF
Evidence: $EVIDENCE   Backups: $BACKUPS   Whitelist: $WHITELIST

 1) Snapshot this host            (os, network, services, accounts, firewall)
 2) Map the network               (authorized TCP scan of assigned hosts)
 3) Back up configs               (+ remind yourself: DB dumps are separate)
 4) Build service watchlist       (from live listeners -> services.local.json)
 5) Watch services                (loop TCP/HTTP/systemd checks)
 6) Audit accounts                (UID 0 dupes, empty passwords, keys, sudo)
 7) Rotate passwords              (whiteteam-safe, list-first, --apply in script)
 8) Database audit                (MySQL/Postgres users, plugins, DBs)
 9) Docker triage                 (containers, ports, mounts - whale host)
10) Firewall: generate rules      (candidate only - never applies)
11) Firewall: apply with rollback (timed auto-undo, whitelist force-allowed)
12) Log a change                  (UTC change log -> feeds IR report)
13) Tool readiness check          (what's missing on this distro)
 0) Exit
EOF
    printf 'choice: '; read -r choice
    case "$choice" in
        1) run_map ;;        2) run_netmap ;;   3) run_backup ;;  4) run_genwatch ;;
        5) run_watch ;;      6) run_accounts ;; 7) run_passwd ;;  8) run_dbs ;;
        9) run_docker ;;     10) run_fwgen ;;   11) run_fwapply ;;
        12) run_log ;;       13) run_ready ;;
        0) exit 0 ;;
        *) echo "unknown choice" ;;
    esac
    pause
done
