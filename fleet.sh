#!/usr/bin/env bash
# Fleet sweeps: run the kit's read-only tools on EVERY host in config/hosts.txt
# simultaneously, from the jumpbox. Output collected per-host in ./evidence/fleet-<stamp>/.
#
# Usage: sh fleet.sh [oscheck|sweep|status|cmd] ...
#   sh fleet.sh oscheck           probe every host: OS verdict + which to comment out
#   sh fleet.sh sweep inventory   snapshot OS/network/services on every host
#   sh fleet.sh sweep accounts    account audit everywhere
#   sh fleet.sh sweep hunt        persistence triage (POST-NOON ONLY, gated)
#   sh fleet.sh sweep docker      container triage everywhere
#   sh fleet.sh sweep dbs         database audit everywhere
#   sh fleet.sh status            uptime + listener count per host
#   sh fleet.sh cmd 'COMMAND'     arbitrary command (typed confirmation required)
#
# hosts.txt entries may use $TEAM (expanded from config/team.conf or the
# TEAM_NUMBER environment variable). Assumes the kit sits at the same path on
# every host (default ~/ccdc-linux-field-kit, override with: KIT_PATH=... sh fleet.sh ...).
set -u
KIT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
HOSTS_FILE="$KIT_ROOT/config/hosts.txt"
KIT_PATH="${KIT_PATH:-\$HOME/ccdc-linux-field-kit}"
STAMP=$(date -u '+%Y%m%dT%H%M%SZ')
OUTDIR="$KIT_ROOT/evidence/fleet-$STAMP"

# Universal team number: config/team.conf, overridable via environment
# (TEAM_NUMBER=7 sh fleet.sh ...). hosts.txt entries may use $TEAM or ${TEAM}.
[ -f "$KIT_ROOT/config/team.conf" ] && . "$KIT_ROOT/config/team.conf"
TEAM_NUMBER=${TEAM_NUMBER:-00}

banner() { printf '%s\n' "=== FLEET team $TEAM_NUMBER ($(date -u '+%H:%M:%SZ')) - evidence: $OUTDIR ==="; }

usage() { sed -n '2,17p' "$0"; exit 2; }

[ -s "$HOSTS_FILE" ] || { echo "config/hosts.txt is empty - add ssh targets first (one per line)"; exit 2; }
mapfile -t RAW_HOSTS < <(grep -vE '^\s*(#|$)' "$HOSTS_FILE" | sed 's/\s*#.*$//')
[ "${#RAW_HOSTS[@]}" -gt 0 ] || { echo "no enabled (uncommented) hosts in config/hosts.txt"; exit 2; }

# Expand $TEAM / ${TEAM} placeholders into concrete ssh targets
TARGETS=()
for line in "${RAW_HOSTS[@]}"; do
    target=${line//'${TEAM}'/$TEAM_NUMBER}
    target=${target//'$TEAM'/$TEAM_NUMBER}
    TARGETS+=("$target")
done

SSH_OPTS=(-o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new)

safe_name() { printf '%s' "$1" | tr '@:/' '___'; }

run_one() {  # $1=host  $2=remote command  $3=log path
    ssh "${SSH_OPTS[@]}" "$1" "$2" >"$3" 2>&1
}

oscheck() {
    banner
    echo "Probing ${#TARGETS[@]} host(s) - 'uname -s; hostname':"
    mkdir -p "$OUTDIR"
    pids=()
    for target in "${TARGETS[@]}"; do
        run_one "$target" "uname -s; hostname" "$OUTDIR/$(safe_name "$target").log" &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    printf '\n%-30s %-22s %s\n' "TARGET" "VERDICT" "ANSWER"
    for target in "${TARGETS[@]}"; do
        answer=$(tr '\n' ' ' < "$OUTDIR/$(safe_name "$target").log" 2>/dev/null)
        case "$answer" in
            *Linux*)    verdict="LINUX - keep enabled" ;;
            *MINGW*|*CYGWIN*|*Windows*) verdict="WINDOWS - comment out" ;;
            ""|*"Permission denied"*|*"denied"*) verdict="AUTH/REACH FAIL - fix ssh first" ;;
            *) verdict="OTHER - inspect manually" ;;
        esac
        printf '%-30s %-22s %s\n' "$target" "$verdict" "${answer:-<no output>}"
    done
    echo
    echo "NEXT: comment out every non-LINUX line in config/hosts.txt, then:"
    echo "  sh fleet.sh sweep inventory"
}

sweep() {
    banner
    mkdir -p "$OUTDIR"
    pids=()
    for target in "${TARGETS[@]}"; do
        case "$1" in
            inventory) remote="sudo -n python3 $KIT_PATH/service/map_environment.py --output /root/evidence" ;;
            accounts)  remote="sudo -n python3 $KIT_PATH/service/audit_accounts.py --output /root/evidence" ;;
            hunt)      remote="sudo -n python3 $KIT_PATH/threat/hunt_persistence.py --output /root/evidence" ;;
            docker)    remote="sudo -n python3 $KIT_PATH/service/docker_triage.py --output /root/evidence" ;;
            dbs)       remote="sudo -n python3 $KIT_PATH/service/db_audit.py --output /root/evidence" ;;
            *) echo "unknown sweep: $1 (inventory|accounts|hunt|docker|dbs)"; return 2 ;;
        esac
        printf '  %-28s -> %s\n' "$target" "$1"
        run_one "$target" "$remote" "$OUTDIR/$(safe_name "$target").log" &
        pids+=($!)
    done
    fail=0
    for pid in "${pids[@]}"; do wait "$pid" || fail=$((fail+1)); done
    echo "done: $((${#TARGETS[@]} - fail)) ok, $fail failed. Per-host summaries:"
    for target in "${TARGETS[@]}"; do
        log="$OUTDIR/$(safe_name "$target").log"
        printf '\n--- %s ---\n' "$target"
        grep -E "^(===|FINDING|WARNING|LISTENING|ESTABLISHED|LOGGED|AUTHORIZED|INTERACTIVE|SUDO|LISTENERS|PERSISTENCE|  )" "$log" 2>/dev/null | head -12 || head -5 "$log" 2>/dev/null
    done
    return 0
}

status() {
    banner
    mkdir -p "$OUTDIR"
    pids=()
    for target in "${TARGETS[@]}"; do
        run_one "$target" "uptime; ss -H -lnt | wc -l" "$OUTDIR/$(safe_name "$target").log" &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    for target in "${TARGETS[@]}"; do
        printf '%-30s | %s\n' "$target" "$(tr '\n' ' | ' < "$OUTDIR/$(safe_name "$target").log" 2>/dev/null)"
    done
}

custom_cmd() {
    printf 'This runs an ARBITRARY command on %d host(s):\n' "${#TARGETS[@]}"
    printf '  %s\n' "${TARGETS[@]}"
    printf '  command: %s\n' "$1"
    printf 'Type RUN to confirm: '; read -r answer
    [ "$answer" = "RUN" ] || { echo "cancelled"; return 1; }
    banner
    mkdir -p "$OUTDIR"
    pids=()
    for target in "${TARGETS[@]}"; do
        run_one "$target" "$1" "$OUTDIR/$(safe_name "$target").log" &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do wait "$pid"; done
    echo "done. logs in $OUTDIR"
}

case "${1:-}" in
    oscheck) oscheck ;;
    sweep)   [ $# -ge 2 ] || usage
             [ "$2" != hunt ] || { printf 'Hunting is POST-NOON ONLY. Type POST-NOON to confirm: '; read -r answer
                                  [ "$answer" = "POST-NOON" ] || { echo "refused - stay in service phase"; exit 1; }; }
             sweep "$2" ;;
    status)  status ;;
    cmd)     [ $# -ge 2 ] || usage; custom_cmd "$2" ;;
    *)       usage ;;
esac
