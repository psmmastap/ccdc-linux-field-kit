#!/usr/bin/env python3
"""Read-only database audit: accounts, grants summary, plugins, databases.

MySQL/MariaDB via root socket auth; PostgreSQL via the postgres OS user.
Never creates/changes anything. Flags accounts with empty password hashes.
Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def capture(argv, timeout=15):
    if not shutil.which(argv[0]):
        return None
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True, errors="replace", check=False)
        return {"argv": argv, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"argv": argv, "returncode": -1, "stdout": "", "stderr": str(exc)}


def mysql_rows(result):
    lines = [l for l in result["stdout"].splitlines() if l.strip()]
    return [l.split("\t") for l in lines]


def audit_mysql():
    if not shutil.which("mysql"):
        return None
    out = {"server": "mysql/mariadb"}
    users = capture(["mysql", "-N", "-B", "-e",
                     "SELECT user, host, plugin, "
                     "(plugin='mysql_native_password' AND (authentication_string='' OR authentication_string IS NULL)) "
                     "FROM mysql.user;"])
    if users and users["returncode"] == 0:
        rows = mysql_rows(users)
        out["users"] = [{"user": r[0], "host": r[1] if len(r) > 1 else "",
                         "plugin": r[2] if len(r) > 2 else "",
                         "empty_password": r[3] == "1" if len(r) > 3 else "?"} for r in rows]
    else:
        out["users_error"] = (users or {}).get("stderr", "mysql client/server not reachable")
    plugins = capture(["mysql", "-N", "-B", "-e", "SHOW PLUGINS;"])
    if plugins and plugins["returncode"] == 0:
        out["plugins"] = [r[:4] for r in mysql_rows(plugins)]
    databases = capture(["mysql", "-N", "-B", "-e", "SHOW DATABASES;"])
    if databases and databases["returncode"] == 0:
        out["databases"] = [r[0] for r in mysql_rows(databases)]
    return out


def audit_postgres():
    psql = shutil.which("psql")
    if not psql or not shutil.which("sudo") and not shutil.which("runuser"):
        return None
    base = ["sudo", "-u", "postgres", "psql", "-At", "-F", "|", "-c"] if shutil.which("sudo") else \
           ["runuser", "-u", "postgres", "--", "psql", "-At", "-F", "|", "-c"]
    out = {"server": "postgresql"}
    roles = capture(base + ["SELECT rolname, rolcanlogin, rolsuper FROM pg_roles ORDER BY rolname;"])
    if roles and roles["returncode"] == 0:
        rows = [l.split("|") for l in roles["stdout"].splitlines() if l.strip()]
        out["roles"] = [{"role": r[0], "can_login": r[1] == "t" if len(r) > 1 else "?",
                         "superuser": r[2] == "t" if len(r) > 2 else "?"} for r in rows]
    else:
        out["roles_error"] = (roles or {}).get("stderr", "not reachable as postgres OS user")
    databases = capture(base + ["SELECT datname FROM pg_database ORDER BY datname;"])
    if databases and databases["returncode"] == 0:
        out["databases"] = [l for l in databases["stdout"].splitlines() if l.strip()]
    extensions = capture(base + ["SELECT extname, extversion FROM pg_extension ORDER BY extname;"])
    if extensions and extensions["returncode"] == 0:
        out["extensions"] = [l for l in extensions["stdout"].splitlines() if l.strip()]
    return out


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence")
    args = p.parse_args()

    out_dir = Path(args.output).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        out_dir.chmod(0o700)
    except OSError:
        pass
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results = [x for x in (audit_mysql(), audit_postgres()) if x]

    print("=== DATABASE AUDIT (read-only) ===")
    empty_found = False
    if not results:
        print("no reachable MySQL/MariaDB or PostgreSQL (client or server absent)")
    for result in results:
        print("-- " + result["server"])
        accounts = result.get("users") or result.get("roles") or []
        for account in accounts:
            flag = ""
            if result["server"].startswith("mysql") and account.get("empty_password") is True:
                flag = "  <<< EMPTY PASSWORD"
                empty_found = True
            if result["server"].startswith("postgres") and account.get("superuser"):
                flag = "  (superuser)"
            print("   %-24s login=%-5s%s" % (account.get("user") or account.get("role"),
                                             str(account.get("can_login", "?")), flag))
        if result.get("users_error") or result.get("roles_error"):
            print("   error: " + str(result.get("users_error") or result.get("roles_error")).strip()[:120])
        print("   databases: " + ", ".join(result.get("databases", [])[:12]))
        if result.get("plugins"):
            print("   plugins: " + ", ".join(":".join(filter(None, p[:2])) for p in result["plugins"][:12]))
    if empty_found:
        print("ACTION: empty-password DB accounts must get passwords or be dropped "
              "(ALTER USER ... IDENTIFIED BY / DROP USER) - then update the apps that use them.")

    path = out_dir / ("databases-" + stamp + ".json")
    path.write_text(json.dumps({"time": dt.datetime.now(dt.timezone.utc).isoformat() + "Z (UTC)",
                                "results": results}, indent=2, default=str) + "\n", encoding="utf-8")
    print("detail: " + str(path))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
