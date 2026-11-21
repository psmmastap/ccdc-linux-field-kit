#!/usr/bin/env python3
"""Interactive, whitelist-safe password rotation for interactive accounts.

RULE 3.5: accounts in config/whitelist.txt (whiteteam by default) are NEVER
rotated, locked or kicked. Rule 3.6 names are also excluded.

Default mode lists accounts and changes NOTHING. Changes require --apply.
Locking an account does NOT terminate its existing sessions or remove SSH keys.

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import pwd
import subprocess
import sys

NOLOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/bin/nologin",
                  "/usr/bin/false", "/usr/bin/nologin", "/bin/true"}
PROTECTED = {"whiteteam"}  # absolute floor; whitelist.txt extends this


def load_whitelist(path):
    names, nets = set(), []
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print("warning: cannot read whitelist %s: %s" % (path, exc), file=sys.stderr)
        return names, nets
    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue
        try:
            import ipaddress
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            names.add(entry)
    return names, nets


def interactive_users():
    rows = []
    for entry in pwd.getpwall():
        rows.append({"name": entry.pw_name, "uid": entry.pw_uid, "shell": entry.pw_shell,
                     "home": entry.pw_dir})
    return rows


def targetable(user):
    return user["uid"] >= 1000 and user["shell"] not in NOLOGIN_SHELLS


def run_change(name, password):
    result = subprocess.run(["chpasswd"], input=name + ":" + password + "\n",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False)
    return result.returncode == 0, (result.stderr or "").strip()


def lock_account(name):
    result = subprocess.run(["passwd", "-l", name], stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, check=False)
    return result.returncode == 0, (result.stdout + result.stderr).strip()


def print_targets(args, whitelist_names):
    users = interactive_users()
    rows, skipped = [], []
    for user in users:
        if user["name"] == "root":
            skipped.append((user, "root - use --include-root to offer it (careful)"))
        elif user["name"] in PROTECTED or user["name"] in whitelist_names:
            skipped.append((user, "PROTECTED (whitelist) - never touches"))
        elif user["name"] in args.skip:
            skipped.append((user, "skipped via --skip"))
        elif not targetable(user):
            skipped.append((user, "system/non-interactive account"))
        else:
            rows.append(user)
    print("%-16s %-8s %-24s %s" % ("ACCOUNT", "UID", "SHELL", "STATUS"))
    for user in rows:
        print("%-16s %-8s %-24s %s" % (user["name"], user["uid"], user["shell"], "ROTATION TARGET"))
    for user, why in skipped:
        print("%-16s %-8s %-24s %s" % (user["name"], user["uid"], user["shell"], why))
    if not rows:
        print("no rotation targets (all accounts protected/system/skipped)")
    return rows


def prompt_password(name):
    for _ in range(3):
        first = getpass.getpass("new password for %s: " % name)
        if len(first) < 12:
            print("  too short (12+ characters); try again")
            continue
        again = getpass.getpass("repeat password: ")
        if first == again:
            return first
        print("  passwords do not match; try again")
    return None


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--whitelist", default="config/whitelist.txt")
    p.add_argument("--apply", action="store_true", help="actually change passwords; default is list only")
    p.add_argument("--include-root", action="store_true", help="also offer root (dangerous; sudo must still work)")
    p.add_argument("--skip", nargs="*", default=[], help="additional account names to leave alone")
    p.add_argument("--lock", metavar="USER", help="lock one account (passwd -l) instead of rotating")
    args = p.parse_args()

    whitelist_names, _ = load_whitelist(args.whitelist)
    if args.lock:
        if args.lock in PROTECTED or args.lock in whitelist_names:
            print("REFUSED: %s is whitelisted (rule 3.5/3.6); locking it can mean disqualification" % args.lock)
            return 2
        ok, detail = lock_account(args.lock)
        print(("LOCKED  " if ok else "FAILED  ") + args.lock + ": " + detail)
        if ok:
            print("NOTE: locking does NOT kill existing sessions. Remove authorized_keys entries,")
            print("      then consider: pkill -u %s   (only after confirming it is not whitelisted)" % args.lock)
        return 0 if ok else 1

    rows = print_targets(args, whitelist_names)
    if args.include_root:
        root = pwd.getpwnam("root")
        if "root" in whitelist_names:
            print("root is whitelisted; --include-root refused")
        else:
            rows.append({"name": "root", "uid": root.pw_uid, "shell": root.pw_shell, "home": root.pw_dir})
            print("root included by --include-root (verify sudo still works BEFORE logging out)")
    if not args.apply:
        print("\nLIST ONLY. Re-run with --apply to rotate. Remember afterwards:")
        print("  1. apps/databases may embed credentials - rotate those and update the apps that use them")
        print("  2. remove unknown authorized_keys entries (locking does not remove keys)")
        return 0
    print()
    changed, failed = 0, 0
    for user in rows:
        password = prompt_password(user["name"])
        if password is None:
            print("SKIPPED " + user["name"])
            failed += 1
            continue
        ok, detail = run_change(user["name"], password)
        print(("CHANGED " if ok else "FAILED  ") + user["name"] + (("  " + detail) if detail and not ok else ""))
        changed += ok
        failed += not ok
    print("\ndone: %d changed, %d failed/skipped" % (changed, failed))
    print("NEXT: rotate DB/app credentials to match, then re-verify scored services.")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted; partially rotated passwords are NOT rolled back", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(2)
