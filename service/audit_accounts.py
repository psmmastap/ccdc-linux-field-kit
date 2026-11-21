#!/usr/bin/env python3
"""Read-only account audit: UID 0 duplicates, empty/locked passwords, SSH keys, sudo.

Morning-phase safe (fixing/maintaining). Findings are observations, not verdicts.
Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import socket
import subprocess
import sys

NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/nologin",
                  "/usr/bin/false", "/usr/bin/nologin", "/bin/true"}


def capture(argv, timeout=15):
    if not shutil.which(argv[0]):
        return {"status": "missing", "stdout": "", "stderr": "command not installed"}
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True, errors="replace", check=False)
        return {"status": "ok" if p.returncode == 0 else "error",
                "stdout": p.stdout, "stderr": p.stderr}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "error", "stdout": "", "stderr": str(exc)}


def audit():
    findings, detail = [], {}

    users = pwd.getpwall()
    zero_uid = [u.pw_name for u in users if u.pw_uid == 0]
    detail["uid0_accounts"] = zero_uid
    if len(zero_uid) > 1:
        findings.append("UID 0 DUPLICATES: %s - non-root UID0 accounts are a classic backdoor; investigate" % ", ".join(zero_uid))

    interactive, system = [], []
    for u in users:
        (interactive if u.pw_uid >= 1000 and u.pw_shell not in NOLOGIN_SHELLS else system).append(
            {"name": u.pw_name, "uid": u.pw_uid, "shell": u.pw_shell, "home": u.pw_dir})
    detail["interactive_accounts"] = interactive
    detail["system_accounts_count"] = len(system)

    # /etc/shadow: needs root; empty hash or no hash = direct-login risk
    shadow_lines = []
    try:
        for line in Path("/etc/shadow").read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) >= 2:
                shadow_lines.append({"name": parts[0], "hash": parts[1]})
    except OSError:
        findings.append("could not read /etc/shadow (need root for password-field checks)")
    empties, odd = [], []
    for row in shadow_lines:
        h = row["hash"]
        if h == "":
            empties.append(row["name"])
        elif h and not h.startswith(("!", "*", "$")) and h != "x":
            odd.append(row["name"])
    if empties:
        findings.append("EMPTY PASSWORD accounts: %s - set a password or lock immediately" % ", ".join(empties))
    if odd:
        findings.append("UNUSUAL password hash format (possibly plaintext/legacy): %s" % ", ".join(odd))
    detail["shadow_entries"] = shadow_lines

    # authorized_keys audit ONLY - private keys and known_hosts are never read
    keys = []
    for u in users:
        for ssh_dir in (Path(u.pw_dir) / ".ssh", Path("/root/.ssh") if u.pw_name == "root" else None):
            if not ssh_dir or not ssh_dir.is_dir():
                continue
            for keyfile in sorted(ssh_dir.glob("authorized_keys*")):
                if not keyfile.is_file():
                    continue
                try:
                    text = keyfile.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                entries = [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
                if not entries:
                    continue
                types, comments = [], []
                for line in entries:
                    parts = line.split()
                    types.append(parts[0] if parts else "?")
                    comments.append(" ".join(parts[2:])[:50] if len(parts) >= 3 else "(no comment)")
                keys.append({"account": u.pw_name, "file": str(keyfile), "entries": len(entries),
                             "types": types, "comments": comments})
    detail["authorized_keys"] = keys
    if keys:
        findings.append("SSH authorized_keys present on %d file(s) - verify every entry is yours (rule: locking accounts does not remove keys)" % len(keys))

    # sudo
    sudo_lines = []
    sudo_paths = [Path("/etc/sudoers")]
    if Path("/etc/sudoers.d").is_dir():
        sudo_paths += sorted(Path("/etc/sudoers.d").glob("*"))
    for path in sudo_paths:
        try:
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    sudo_lines.append({"file": str(path), "line": stripped})
        except OSError:
            pass
    detail["sudo_rules"] = sudo_lines
    nopasswd = [r["line"] for r in sudo_lines if "NOPASSWD" in r["line"]]
    if nopasswd:
        findings.append("NOPASSWD sudo rules: %d - review each (passwordless root for who?)" % len(nopasswd))

    # sessions and logins
    detail["who"] = capture(["w", "-h"])
    detail["last"] = capture(["last", "-n", "15"])
    who_now = [l for l in (detail["who"]["stdout"] or "").splitlines() if l.strip()]
    if who_now:
        findings.append("currently logged in: %d session(s) - confirm each is yours/team" % len(who_now))

    return findings, detail


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", default="./evidence")
    args = parser.parse_args()

    out = Path(args.output).expanduser()
    out.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        out.chmod(0o700)
    except OSError:
        pass
    findings, detail = audit()
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    (out / ("accounts-" + stamp + ".json")).write_text(
        json.dumps({"time": dt.datetime.now(dt.timezone.utc).isoformat() + "Z (UTC)",
                    "findings": findings, "detail": detail}, indent=2, default=str) + "\n", encoding="utf-8")

    print("=== ACCOUNT AUDIT (read-only) === host: %s" % socket.gethostname())
    for f in findings:
        print("FINDING: " + f)

    keys = detail["authorized_keys"]
    sudo_lines = detail["sudo_rules"]
    sessions = [l for l in (detail["who"]["stdout"] or "").splitlines() if l.strip()]
    print("LOGGED IN NOW (%d):" % len(sessions))
    for line in sessions[:10]:
        print("  " + line.rstrip())
    if detail["who"]["status"] != "ok":
        print("  (w unavailable: %s)" % detail["who"]["stderr"].strip()[:60])

    print("AUTHORIZED KEYS:")
    for k in keys[:15]:
        print("  %-14s %-40s %d key(s)" % (k["account"], k["file"].replace("/home/", "~/"), k["entries"]))
        for ktype, comment in list(zip(k["types"], k["comments"]))[:4]:
            print("      %s  %s" % (ktype.replace("ssh-", ""), comment))
    if len(keys) > 15:
        print("  ... +%d more files in the detail JSON" % (len(keys) - 15))

    names = ", ".join(u["name"] for u in detail["interactive_accounts"])
    print("INTERACTIVE ACCOUNTS (%d): %s" % (len(detail["interactive_accounts"]), names or "none"))
    print("SUDO RULES (%d):" % len(sudo_lines))
    for rule in sudo_lines[:10]:
        print("  %s: %s" % (rule["file"].replace("/etc/", ""), rule["line"][:110]))
    if len(sudo_lines) > 10:
        print("  ... +%d more rules in the detail JSON" % (len(sudo_lines) - 10))
    print("detail: %s" % (out / ("accounts-" + stamp + ".json")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
