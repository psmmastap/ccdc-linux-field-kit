# Cheat sheet: same task, Debian vs RHEL family

Verify per host first (never assume): `cat /etc/os-release`; `cat /proc/1/comm` (systemd or not); `command -v apt dnf`.

Debian/Ubuntu = `apt`, `/var/log/auth.log`, `ssh` unit, `apache2`.
RHEL/Rocky/Fedora = `dnf`, `/var/log/secure`, `sshd` unit, `httpd`.

## Packages (install ONLY approved tools; never `upgrade` all on a scored host)

| Tool | Debian/Ubuntu | RHEL family |
|---|---|---|
| `dig` | `dnsutils` | `bind-utils` |
| `lsof` | `lsof` | `lsof` |
| `nc` | `netcat-openbsd` | `nmap-ncat` |
| `tcpdump` | `tcpdump` | `tcpdump` |
| `strace` | `strace` | `strace` |
| `getcap` | `libcap2-bin` | `libcap` |
| `getfacl`/`getfattr` | `acl`/`attr` | `acl`/`attr` |
| auditd | `auditd` | `audit` |

`sh prepare_box.sh --profile all --plan` prints exactly what's missing + candidate package names.

## Services

```bash
systemctl status UNIT --no-pager          # unit traps: ssh vs sshd, apache2 vs httpd
systemctl list-units --type=service       # what's running
systemctl list-timers --all               # cron alternative
journalctl -u UNIT -n 100 --no-pager      # why it won't start
journalctl -u ssh -u sshd --no-pager -n 200   # auth via journal
```

## Network

```bash
ip -br addr; ip route
ss -lntup                 # listeners with PIDs (root)
ss -ntup                  # established connections - your C2/scan starting point
cat /etc/resolv.conf      # attacker-changed DNS = silent redirects
```

## Firewall state (identify the manager BEFORE changing anything)

```bash
iptables-save; ip6tables-save       # legacy / iptables-nft
nft list ruleset                     # native nftables
firewall-cmd --state; firewall-cmd --list-all   # firewalld (RHEL default)
ufw status verbose                   # ufw (Ubuntu)
```

One host has ONE managing tool; others report through compatibility layers. Docker-published ports use FORWARD, not INPUT. Apply changes only via `service/firewall_apply.py` (state save + timed rollback + whitelist force-allow).

## Passwords & accounts

```bash
passwd USER                                   # interactive, per account (whiteteam NEVER)
passwd -l USER                                # lock (does NOT kill sessions or remove keys)
awk -F: '($3 == 0) {print}' /etc/passwd       # UID 0 duplicates - classic backdoor
w; last -n 30; lastb -n 50                    # sessions / logins / failed logins
sudo python3 service/audit_accounts.py        # all of the above, read-only
```

## Post-noon hunting quick commands

```bash
# cron & timers
for user in $(cut -f1 -d: /etc/passwd); do echo $user; crontab -u $user -l 2>/dev/null; done
cat /etc/crontab /etc/cron.d/* 2>/dev/null; systemctl list-timers --all

# SSH keys everywhere (incl. root, www-data)
find / -name authorized_keys 2>/dev/null

# SUID / world-writable / recent
find /etc /var/www /tmp /var/tmp /dev/shm /home /root/.ssh -xdev -type f \( -perm -6000 -o -perm -0002 \) -ls 2>/dev/null
find /etc /var/www -xdev -type f -mmin -240 -ls 2>/dev/null

# rootkit indicators
cat /etc/ld.so.preload                        # should not exist (chattr -i first if immutable)
cat /proc/sys/kernel/tainted                  # 0 = clean
lsmod | cut -d' ' -f1 | sort > /tmp/a; ls /sys/module | sort > /tmp/b; diff /tmp/a /tmp/b

# service that won't start
journalctl -xeu UNIT; ss -lntup | grep <port>; df -h
```

## Database quick refs

MySQL/MariaDB: `mysql -u root -p` · `SELECT user,host,plugin FROM mysql.user;` · `SHOW PLUGINS;` · `ALTER USER 'u'@'h' IDENTIFIED BY '...';` · `DROP USER 'u'@'h';`
MSSQL (sting): `sqlcmd -S localhost -U sa -P '...'` · `SELECT name FROM sys.databases;` · `SELECT name FROM sys.sql_logins;` · `ALTER LOGIN sa WITH PASSWORD = '...';` — scored login: sa. Port 1433.
PostgreSQL: `sudo -u postgres psql` · `SELECT rolname,rolcanlogin,rolsuper FROM pg_roles;` · `\du` · `\l` · `ALTER ROLE r WITH PASSWORD '...';` · `\dx`
SQLite: never copy a live DB/WAL file—use `sqlite3 DB ".backup 'out.db'"`.
Read-only sweep of both: `sudo python3 service/db_audit.py`.

## Docker (whale host)

```bash
docker ps -a; docker images; docker network ls
docker inspect <c> | jq '.[0].Mounts, .[0].HostConfig.PortBindings'
docker logs <c>; docker exec -it <c> /bin/bash
sudo python3 service/docker_triage.py        # read-only sweep incl. privileged/host-net flags
```

Published ports traverse FORWARD/DNAT (host INPUT rules don't protect them). `docker commit` excludes volumes.

## Restore workflow (backups.py archives = GNU tar, paths relative to /)

```bash
# verify first, then STAGE - never blind-overwrite /etc
sha256sum -c SHA256SUMS
tar -tzf files.tar.gz > /tmp/listing.txt
mkdir -p /root/restore-stage && tar -xzf files.tar.gz -C /root/restore-stage etc
diff -rq /root/restore-stage/etc /etc                 # see exactly what differs
cp -a /root/restore-stage/etc/nginx/nginx.conf /etc/nginx/nginx.conf   # selective
nginx -t && systemctl reload nginx                    # syntax test, then reload

# full /etc rollback = LAST RESORT (also reverts whitelist/PAM/sshd fixes!)
tar -xzf files.tar.gz -C / --numeric-owner etc/ && systemctl daemon-reload
```

Databases restore as SQL, not tar: `mysql --defaults-extra-file=/root/mysql-backup.cnf < dump.sql` / `sudo -u postgres psql -f dumpall.sql`. Never copy live DB data files back. Docker: `docker load -i backup.tar` + recreate volumes from volume tars.

## Persistence checklist (post-noon — hunt_persistence.py covers most of this)

- `/etc/cron*`, `/var/spool/cron/`, per-user `crontab -l`
- `/etc/systemd/system/`, `/usr/lib/systemd/system/` (units, timers, **generators**)
- `~/.ssh/authorized_keys` (every user), `/etc/ssh/sshd_config` + includes, `/etc/ssh/sshrc`
- `/etc/ld.so.preload` (should not exist), `/etc/sudoers` + `sudoers.d/`, `/etc/pam.d/`
- `~/.bashrc`, `~/.profile`, `/etc/profile.d/`, `/etc/apt/apt.conf.d/` (Pre-Invoke hooks)
- `getfacl` odd ACLs; `lsattr` immutable bits; `getcap -r /usr/bin /usr/sbin`
