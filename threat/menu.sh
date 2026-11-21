#!/usr/bin/env bash
# THREAT menu - POST-NOON PHASE ONLY (12:00+ per tryout rules).
# Hunting or implant removal BEFORE 12:00 = DISQUALIFICATION. This menu enforces it.
set -u
KIT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -f "$KIT_ROOT/config/team.conf" ] && . "$KIT_ROOT/config/team.conf"
EVIDENCE="${EVIDENCE_DIR:-/root/evidence}"
WHITELIST="$KIT_ROOT/config/whitelist.txt"
SUDO=""
[ "$(id -u)" = 0 ] || SUDO="sudo"

confirm_phase() {
    clear 2>/dev/null || true
    cat <<'EOF'
=== THREAT MENU ===
Rules check: hunting/removal is authorized ONLY after 12:00.
Type POST-NOON to confirm the official transition has happened:
EOF
    printf '> '; read -r answer
    [ "$answer" = "POST-NOON" ] || { echo "not confirmed - stay in service/menu.sh until the transition."; exit 1; }
}

pause() { printf '\n[enter to return to menu] '; read -r _; }

run_hunt()     { $SUDO python3 "$KIT_ROOT/threat/hunt_persistence.py" --output "$EVIDENCE"; }
run_baseline() { printf 'Paths to baseline (default: /etc /var/www): '; read -r input
                 paths=(${input:-/etc /var/www}); $SUDO python3 "$KIT_ROOT/threat/baseline_files.py" --paths "${paths[@]}" --output "$EVIDENCE"; }
run_compare()  { printf 'BEFORE baseline.json path: '; read -r before
                 printf 'AFTER  baseline.json path: '; read -r after
                 python3 "$KIT_ROOT/threat/compare_baselines.py" --before "$before" --after "$after" --output "$EVIDENCE"; }
run_authlog()  { python3 "$KIT_ROOT/threat/log_triage.py" --output "$EVIDENCE"; }
run_docker()   { $SUDO python3 "$KIT_ROOT/service/docker_triage.py" --output "$EVIDENCE"; }
run_beacons()  { printf 'connection-starts CSV path (from your capture/auditd): '; read -r csv
                 python3 "$KIT_ROOT/threat/hunt_beacons.py" --input "$csv" --output "$EVIDENCE"; }
run_auditd()   { printf 'install / remove / status: '; read -r action
                 action=${action#--}; $SUDO sh "$KIT_ROOT/threat/beacon_logging.sh" "--$action"; }
run_report()   { sh "$KIT_ROOT/threat/report_template.sh" "$EVIDENCE"; }
run_log()      { printf 'What did you do: '; read -r text; sh "$KIT_ROOT/service/changelog.sh" "$text"; }

confirm_phase
while true; do
    clear 2>/dev/null || true
    cat <<EOF
=== THREAT MENU (post-noon) ===
Evidence: $EVIDENCE   Whitelist: $WHITELIST

 1) Persistence triage           (cron/systemd/SSH keys/loaders/SUID - LEADS not verdicts)
 2) Baseline files now           (snapshot for later diff)
 3) Compare baselines            (morning vs now)
 4) Auth log triage              (failed logins by IP, accepted logins, sudo, new users)
 5) Docker triage                (containers are invisible to host hunts)
 6) Beacon timing                (rank connection-start CSV by regularity)
 7) Beacon logging (auditd)      (install/remove/status - then ausearch -k beacon_network)
 8) IR report template           (pre-filled; feeds your change log in)
 9) Log a change                 (UTC change log)
 0) Exit

Workflow per finding: socket -> PID (ss -p, /proc/PID/exe) -> path+hash ->
persistence mechanism -> evidence -> targeted reversible removal (with approval).
NEVER: execute suspects, mass-block, delete before preserving, touch whitelisted items.
EOF
    printf 'choice: '; read -r choice
    case "$choice" in
        1) run_hunt ;;      2) run_baseline ;; 3) run_compare ;; 4) run_authlog ;;
        5) run_docker ;;    6) run_beacons ;;  7) run_auditd ;;  8) run_report ;;
        9) run_log ;;
        0) exit 0 ;;
        *) echo "unknown choice" ;;
    esac
    pause
done
