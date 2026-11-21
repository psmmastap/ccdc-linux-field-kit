#!/bin/sh
# Create a ready-to-fill incident response report (rule 3.4: clear, detailed, ON TIME).
# Pre-fills team, host, timeline skeleton and pulls your change log entries in.
# Usage: sh report_template.sh [output-dir]
set -u
OUT=${1:-./evidence}
umask 077

KIT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
[ -f "$KIT_ROOT/config/team.conf" ] && . "$KIT_ROOT/config/team.conf"
TEAM=${TEAM_NUMBER:-00}
CHANGELOG=$(ls -t "$OUT"/change-log.txt ../change-log.txt 2>/dev/null | head -n 1 || true)

mkdir -p "$OUT" || exit 2
FILE="$OUT/ir-report-$(date -u '+%Y%m%dT%H%M%SZ').md"
HOST=$(hostname)

{
cat <<EOF
# Incident Response Report - Team $TEAM - $HOST

**Generated (UTC):** $(date -u '+%Y-%m-%dT%H:%M:%SZ')
**Status:** DRAFT - delete this line when submitted

## Summary
<!-- 2-4 sentences: what happened, impact on scored services, current state -->

## Timeline (ALL TIMES UTC - convert with: date -u -d "@<epoch>")
| Time (UTC) | Event | Evidence |
|---|---|---|
|  | first observation |  |
|  | investigation |  |
|  | action taken |  |
|  | result |  |

## Hosts Affected
| Hostname | IP | Role | Impact |
|---|---|---|---|
| $HOST | $(hostname -I 2>/dev/null | awk '{print $1}') |  |  |

## Findings
<!-- per finding: what, where (path/port/PID), how identified, confidence -->

## Actions Taken
EOF
if [ -n "${CHANGELOG:-}" ] && [ -f "$CHANGELOG" ]; then
    printf '%s\n' '<!-- pulled from your change log -->' '' '```'
    cat "$CHANGELOG"
    printf '%s\n' '```' ''
else
    printf '%s\n' '<!-- no change-log.txt found; list actions manually. Use service/changelog.sh next time -->' '' '```' '```' ''
fi
cat <<EOF
## Evidence Locations (kept on assigned infrastructure ONLY - rule 2.5)
- tool output: $OUT
- backups:
- pcaps/logs:

## Remaining Risk
<!-- what you could NOT fix, and what red team may still have -->

## Recommendations
<!-- hardening that should outlast today -->
EOF
} > "$FILE"

printf '%s\n' "report template: $FILE" \
  'Fill it in EARLY - a submitted 80% report beats a perfect one that misses the deadline.' \
  "Your change log (service/changelog.sh) feeds the Actions Taken section automatically."
