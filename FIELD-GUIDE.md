# Field guide: competition day workflow

Primary interface is the two menus. Timings are practice targets; injects and scoring outrank them.

```bash
sh service/menu.sh   # morning: fix & maintain only
sh threat/menu.sh    # post-noon only (requires typing POST-NOON)
```

Day-of setup first: `config/team.conf`, `config/whitelist.txt` (day's whitelisted IPs/processes), `config/known-users.txt`.

## First 15 minutes (morning = service maintenance only)

1. Record assigned hosts/IPs, connection method, scoreboard services, deadlines, whitelists. Verify `whiteteam` exists and note it as untouchable. Fill `config/hosts.txt` with every assigned box.
2. From the jumpbox: `sh fleet.sh sweep inventory` — all hosts snapshotted in parallel. Skim each host's listeners/OS; anything unexplainable goes on the triage list (post-noon).
3. `prepare_box.sh --plan` where tools are missing; install only explicitly approved missing tools.
4. Backups before changes (`backups.py` + native DB dumps, below). Verify exit codes and hashes. Keep everything on assigned infrastructure.
5. Menu items 4-5: build the watchlist from live listeners, then watch services from the jumpbox + watch the scoreboard. Fix with syntax tests, one small reversible change at a time — menu item 12 logs every change (UTC).

## Native service checks (from a permitted second host)

## Native service checks (from a permitted second host)

| Service | Check |
|---|---|
| Web | `curl --fail --max-time 5 http://HOST/` — expect status AND correct content |
| DNS | `dig @DNS_IP expected.name A +time=2 +tries=1` (add `+tcp` for TCP) |
| PostgreSQL | `pg_isready -h DB_HOST -t 3` |
| MySQL/MariaDB | native client with protected option file: `SELECT 1;` |
| SSH | open a NEW session from the approved source |
| systemd | `systemctl status UNIT --no-pager` + `journalctl -u UNIT -n 100 --no-pager` |

Before config edits: `sshd -t`, `nginx -t`, `apachectl configtest`, `postfix check` (product-dependent). After any reload, re-verify service AND scoreboard. A service that won't start: read `journalctl -xeu UNIT`, check `ExecStart`, port ownership (`ss -lntup`), disk space, permissions. Never restart-loop.

## Backups that can be restored

```bash
sudo python3 service/backups.py --paths /etc /var/www /opt --output /root/backups
# Immediately verify: exit code 0, manifest "verified-readable", SHA256SUMS present.
# Nonempty archive is NOT success; nonzero tar exit = incomplete.

# MySQL/MariaDB (option file first, never passwords on the command line):
mysqldump --defaults-extra-file=/root/mysql-backup.cnf \
  --all-databases --single-transaction --routines --events --triggers > /root/backups/mysql.sql
# PostgreSQL:
sudo -u postgres pg_dumpall > /root/backups/postgres.sql
# Then: inspect $? immediately for both.
```

Docker: `docker commit` EXCLUDES volumes; record mounts/back up volumes separately. A readable archive is not a tested restore—restores are rehearsed pre-event on disposable VMs, not improvised on the live host.

## Credentials (coordinated, unique, dependency-aware)

Menu item 6 audits accounts, menu item 7 rotates passwords (list-first; nothing changes until the script's `--apply` mode; whitelisted accounts are refused). Details:

- Interactive `passwd USER` per account; PostgreSQL `\password ROLE`. Never batch-reset UID≥1000 to one password. `whiteteam` and protected identities are never offered.
- Locking an account does NOT kill existing sessions/keys/tokens—remove keys (`authorized_keys` per user), then rotate app/DB credentials and update the apps that use them.
- SSH config changes: `sshd -T` to verify effective config, `sshd -t` before restart, keep a working session open, test a NEW login, then retire old access.
- App configs may embed DB credentials—rotate together and re-verify scoring.

## Firewall (generate → rehearse → apply with rollback)

1. Identify the manager first: `iptables-save`, `nft list ruleset`, `firewall-cmd --state`, `ufw status`. Don't stack managers.
2. Build the real matrix: scoring engine sources, admin sources, client sources, app→DB, DNS, mail. Include IPv6. Honor whitelisted IPs — put them in `config/whitelist.txt`; the apply script force-allows them above every other rule.
3. Menu item 10 (`firewall_rules.py`) writes candidate `.rules` files after you edit the JSON and set `reviewed_for_this_host: true`.
4. Menu item 11 (`firewall_apply.py --apply --approved`): saves pre-change state (both families) to `/root/ccdc-firewall-<stamp>/`, schedules rollback via `systemd-run` (or detached process) in 5 minutes — it survives your SSH dying — then applies with `--noflush`. Verify a NEW SSH session + scored transactions, then `--confirm --state-file ...` to cancel. If you can't reconnect, do nothing; rollback fires.
5. Existing SSH sessions surviving ≠ firewall correct. Never `--confirm` before a NEW login and a scored transaction pass.

Docker-published ports traverse FORWARD/DNAT, not INPUT. Egress stays unrestricted by design—these rules are not C2 containment.

## Post-noon hunting phase

Use `threat/menu.sh` (it enforces the POST-NOON confirmation). Menu order mirrors the workflow:

```bash
sudo python3 threat/log_triage.py --output /root/evidence          # failed logins, accepted logins, sudo, new users
sudo python3 threat/hunt_persistence.py --output /root/evidence    # cron/systemd/keys/loaders/SUID/tmp-exe leads
sudo python3 threat/docker_triage.py --output /root/evidence       # containers are invisible to host hunts
sudo python3 threat/baseline_files.py --paths /etc /var/www --output /root/evidence
python3 threat/compare_baselines.py --before .../baseline.json --after .../baseline.json --output /root/evidence
python3 threat/hunt_beacons.py --input starts.csv --output /root/evidence
sudo sh threat/beacon_logging.sh --install                          # auditd heartbeat rules, then ausearch -k beacon_network
sh threat/report_template.sh /root/evidence                         # pre-filled IR report
```

Workflow per finding: connection/socket → owning PID (`ss -p`, `/proc/PID/exe`, `ps`) → executable path/hash → persistence mechanism (unit, cron, timer, rc, loader, key) → evidence → targeted reversible removal with approval. Bounded capture if permitted: `sudo timeout 120 tcpdump -i eth0 -nn -s 128 -c 2000 -w /root/evidence/net.pcap`.

Never: execute suspect binaries, `killall` blindly, delete before preserving, disable SELinux/AppArmor, unload modules, mass-firewall-block, or remove whitelisted items. Regular timing is a lead, not a verdict; scoring/monitoring traffic also repeats.

## Injects and reporting

Monitor the scoreboard continuously; submit in the requested format before deadlines. Incident reports: `threat/report_template.sh` pre-fills team, host, timeline and pulls in your `change-log.txt` — fill it in early, a submitted 80% report beats a perfect one that misses the deadline. Reboot/revert requests via `black-team-requests` Discord with **team number, hostname, IP, REBOOT or REVERT**—revert destroys your changes; last resort only.

## Distro reality checks

Don't assume unit names, log paths or package names. Verify per host: `cat /etc/os-release`, PID 1 (`/proc/1/comm`), `systemctl`/`rc-service` presence. Details in CHEATSHEET.md. Alpine/OpenRC and non-systemd hosts won't have journald or GNU tool defaults—check tar/ps provenance before trusting backup/inventory output.
