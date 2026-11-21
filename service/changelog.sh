#!/bin/sh
# Append-only competition change log. One line per action, UTC timestamped.
# The FIELD GUIDE and rule 3.4 (clear, detailed, on-time reports) both depend on this.
# Usage:
#   sh changelog.sh "stopped suspicious cron /etc/cron.d/update"
#   sh changelog.sh --show [N]     show last N entries (default 20)
set -u
LOG=${KIT_CHANGELOG:-./change-log.txt}

usage() {
    printf '%s\n' 'Usage: sh changelog.sh "what you did and why"' \
      '       sh changelog.sh --show [N]' \
      "Log file: \$KIT_CHANGELOG (default: $LOG)"
    exit 2
}

[ $# -ge 1 ] || usage

case "$1" in
    --show)
        n=${2:-20}
        tail -n "$n" "$LOG" 2>/dev/null || printf '%s\n' "(empty - no entries yet)"
        ;;
    -h|--help) usage ;;
    *)
        stamp=$(date -u '+%Y-%m-%dT%H:%M:%SZ')
        host=$(hostname)
        printf '%s | %s | %s\n' "$stamp" "$host" "$*" >> "$LOG"
        printf '%s | %s | %s\n' "$stamp" "$host" "$*"
        ;;
esac
