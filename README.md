# CCDC Linux field kit

Competition toolkit for the 2026 CCDC tryouts (Linux role). **Two folders, two menus:**
`service/` for the morning phase, `threat/` for post-noon hunting. Every script is
standalone, needs no pip packages (Python 3.8+ stdlib), and prints a one-screen verdict
instead of a data dump. Full detail always lands in `--output` (private, 0700).

## Rules that override everything

- **No threat hunting or implant removal before 12:00.** Early hunting = DQ. Morning = fix and maintain services + injects.
- **Keep `whiteteam` unchanged**: never rotate, lock, remove or restrict it, and don't break its access indirectly (PAM/SSH/firewall).
- **Honor the day's whitelisted processes/IPs.** Never kill whitelisted binaries or block whitelisted addresses. Enter them in `config/whitelist.txt` FIRST THING - every script enforces it.
- **No export of competition technical information** to laptops, cloud, VirusTotal, or any external service. Evidence/backups/captures stay on assigned infrastructure.
- **No AI tools during the event** (only Google's search AI overview). These scripts are pre-approved by officials.
- Malwarebytes and simplewall are prohibited. Operate only in your assigned environment.

## Day-of setup (do this BEFORE the competition starts)

1. `config/team.conf` - team number, evidence/backup dirs.
2. `config/whitelist.txt` - day's whitelisted IPs/processes + any account besides `whiteteam` you must not touch.
3. `config/known-users.txt` (copy from `known-users.example.txt`) - accounts that existed at handoff; the auditor flags new ones.
4. Copy the whole folder to each assigned host via your approved transfer path (e.g. `scp -r` from the jumpbox). Copying installs nothing.

## Run it

```bash
sh service/menu.sh   # morning phase: fix & maintain (ON a host)
sh threat/menu.sh    # post-noon ONLY: prompts you to type POST-NOON first
```

## Many boxes at once (from the jumpbox)

```bash
# 1. fill config/hosts.txt with one ssh target per line (root@192.168.7.53, ...)
# 2. parallel sweeps - every host at once, output collected per-host:
sh fleet.sh status              # uptime + listener count per host
sh fleet.sh sweep inventory     # map_environment everywhere
sh fleet.sh sweep accounts      # account audit everywhere
sh fleet.sh sweep hunt          # persistence triage (POST-NOON gate applies)
# 3. central watch: check_services.py from the jumpbox covers all hosts' services
# 4. interactive work: tmux, one window per host (Ctrl+B c new, Ctrl+B w list)
```

Fleet sweeps need the kit at the same path on every host (default `~/ccdc-linux-field-kit`,
override with `KIT_PATH=/path sh fleet.sh ...`) and working SSH auth from the jumpbox
(root keys, or `ssh-agent` forwarding from your laptop: `ssh -A jumpbox`).

## service/ (morning phase)

| Tool | What it does | Safety |
|---|---|---|
| `menu.sh` | The morning interface | Shows allowed actions only |
| `map_environment.py` | Host snapshot: OS, network, services, accounts, firewall | Read-only |
| `map_network.py` | Scoped TCP scan of assigned hosts | Requires `--authorized`; no UDP |
| `backups.py` | Verified GNU tar backups + SHA-256 | Not a DB backup - dump DBs separately |
| `gen_services.py` | Builds a service watchlist from live listeners | Edit `contains=` strings before trusting |
| `check_services.py` | Looping TCP/HTTP/systemd health checks | Never restarts anything |
| `audit_accounts.py` | UID 0 dupes, empty passwords, keys, sudo, sessions | Read-only |
| `rotate_passwords.py` | Interactive password rotation + `--lock` | **List-only until `--apply`; whitelist accounts refused** |
| `db_audit.py` | MySQL/Postgres users, plugins, databases | Read-only |
| `docker_triage.py` | Containers, ports, mounts, risky configs | Read-only |
| `firewall_rules.py` | Generates candidate INPUT rules | Never applies |
| `firewall_apply.py` | Applies candidates WITH timed rollback | Saves state, schedules rollback outside SSH, force-allows whitelisted IPs, refuses without `--approved` |
| `changelog.sh` | UTC change log | Feeds the IR report |

## threat/ (post-noon only)

| Tool | What it does | Safety |
|---|---|---|
| `menu.sh` | The hunting interface | Requires typing POST-NOON |
| `hunt_persistence.py` | Cron/systemd/SSH keys/loaders/SUID/tmp-exe triage | Leads, not verdicts |
| `baseline_files.py` + `compare_baselines.py` | Snapshot and diff files vs morning | Detection only |
| `log_triage.py` | Failed logins by IP, accepted logins, sudo, useradd events | Read-only |
| `docker_triage.py` | Container triage (invisible to host hunts) | Read-only |
| `hunt_beacons.py` | Ranks connection-start CSV by timing regularity | Heuristic; scoring traffic repeats too |
| `beacon_logging.sh` | Installs/removes auditd beacon rules | Marked file, clean teardown |
| `report_template.sh` | Pre-filled IR report (rule 3.4) | Pulls your change log in |

## Getting help fast

- Field procedure and priorities: **FIELD-GUIDE.md**
- Same task on a different distro: **CHEATSHEET.md**
- Missing tools per distro: `sh prepare_box.sh --profile all --plan`

## Approval manifest (pre-approved; show this page if asked)

All scripts: standalone, read-only by default, no network listeners, no auto-updates,
no external uploads - all output stays in `--output` on the assigned host. State-changing
actions are gated behind explicit flags (`--apply --approved`, `--install --approved`,
menu POST-NOON confirmation). `prepare_box.sh` is POSIX sh; the rest require Python 3.8+.
