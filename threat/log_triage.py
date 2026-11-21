#!/usr/bin/env python3
"""Auth-log triage: failed logins by source, accepted logins, sudo, new users.

Distro-aware: /var/log/auth.log (Debian/Ubuntu) or /var/log/secure (RHEL family),
falling back to journalctl. Post-noon hunting or any time logs need answers.
Read-only.
Standalone script. Python 3.8+, standard library only.
"""
import argparse
import collections
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

AUTH_LOGS = ["/var/log/auth.log", "/var/log/secure", "/var/log/messages"]

PATTERNS = [
    ("failed_password", re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")),
    ("failed_publickey", re.compile(r"Failed publickey for (?:invalid user )?(\S+) from (\S+)")),
    ("accepted", re.compile(r"Accepted (?:\S+) for (?:invalid user )?(\S+) from (\S+)")),
    ("invalid_user", re.compile(r"Invalid user (\S+) from (\S+)")),
    ("sudo", re.compile(r"(\S+) : .+? ; USER=(\S+) ?; COMMAND=(.*)")),
    ("useradd", re.compile(r"useradd\[\d+\]: new (?:user|group): (?:name=(\S+))")),
    ("session_root", re.compile(r"session opened for user root")),
    ("breakin", re.compile(r"POSSIBLE BREAK-IN ATTEMPT")),
]


def sources():
    for candidate in AUTH_LOGS:
        if Path(candidate).is_file():
            return ["tail", "-n", "20000", candidate], candidate
    if shutil.which("journalctl"):
        return (["journalctl", "-u", "ssh", "-u", "sshd", "-n", "20000", "--no-pager"],
                "journalctl (ssh units)")
    return None, None


def triage(lines):
    counts = {name: collections.Counter() for name in ("failed_password", "failed_publickey",
                                                       "invalid_user", "accepted")}
    accepted_rows, sudo_rows, new_users, breakins = [], [], [], []
    for line in lines:
        for name, pattern in PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            if name == "sudo":
                sudo_rows.append(line.strip()[:180])
            elif name == "useradd":
                new_users.append(line.strip()[:180])
            elif name == "session_root":
                accepted_rows.append(line.strip()[:180])
            elif name == "breakin":
                breakins.append(line.strip()[:160])
            else:
                user, source = match.group(1), match.group(2)
                counts[name][source] += 1
                if name == "accepted":
                    accepted_rows.append(line.strip()[:180])
    return counts, accepted_rows, sudo_rows, new_users, breakins


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence")
    p.add_argument("--top", type=int, default=10)
    args = p.parse_args()

    out_dir = Path(args.output).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        out_dir.chmod(0o700)
    except OSError:
        pass

    cmd, label = sources()
    if not cmd:
        print("no auth log source found (checked %s and journalctl)" % ", ".join(AUTH_LOGS))
        return 1
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=30, text=True, errors="replace", check=False)
        lines = result.stdout.splitlines()
    except (subprocess.TimeoutExpired, OSError) as exc:
        print("could not read logs: %s" % exc)
        return 1

    counts, accepted, sudo_rows, new_users, breakins = triage(lines)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out_dir / ("authlog-" + stamp + ".json")).write_text(json.dumps({
        "time": dt.datetime.now(dt.timezone.utc).isoformat() + "Z (UTC)", "source": label,
        "failed_password_by_source": dict(counts["failed_password"].most_common(200)),
        "failed_publickey_by_source": dict(counts["failed_publickey"].most_common(200)),
        "invalid_user_by_source": dict(counts["invalid_user"].most_common(200)),
        "accepted_logins_tail": accepted[-100:], "sudo_tail": sudo_rows[-100:],
        "useradd_events": new_users[-50:], "breakin_attempts": breakins[-20:],
    }, indent=2) + "\n", encoding="utf-8")

    print("=== AUTH LOG TRIAGE === source: %s (%d lines)" % (label, len(lines)))
    for title, counter in (("failed passwords", counts["failed_password"]),
                           ("failed keys", counts["failed_publickey"]),
                           ("invalid users", counts["invalid_user"])):
        if counter:
            top = ", ".join("%s(%d)" % (ip, n) for ip, n in counter.most_common(args.top))
            print("%s: %s" % (title, top))
    for row in accepted[-10:]:
        print("LOGIN: " + row)
    for row in new_users[-10:]:
        print("NEW USER: " + row)
    if sudo_rows:
        print("sudo commands (last %d):" % min(5, len(sudo_rows)))
        for row in sudo_rows[-5:]:
            print("  " + row)
    for row in breakins[-5:]:
        print("BREAK-IN: " + row)
    print("detail: %s" % (out_dir / ("authlog-" + stamp + ".json")))
    print("NEXT: cross-check every accepted login and source IP against the day's whitelist and your own sessions.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
