#!/usr/bin/env python3
"""Generate a check_services.py watchlist from what is actually listening now.

Runs `ss -H -lntp`, maps each listener to a TCP or HTTP check (and a systemd
unit guess), and writes a services.local.json you can review and edit.
Edit the generated file: set `contains` strings for HTTP checks so a defaced
or wrong-content site still counts as FAIL.
Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HTTP_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000}
UNIT_GUESSES = {
    "nginx": ["nginx"], "apache": ["apache2", "httpd"], "httpd": ["httpd", "apache2"],
    "sshd": ["ssh", "sshd"], "mysqld": ["mysql", "mariadb"], "mariadbd": ["mariadb", "mysql"],
    "postgres": ["postgresql"], "named": ["named", "bind9"], "postfix": ["postfix"],
    "dovecot": ["dovecot"], "gitea": ["gitea"], "dockerd": ["docker"],
}


def parse_ss(text):
    listeners = []
    for line in text.splitlines():
        match = re.match(r"(\S+)\s+\S+\s+\S+\s+(\S+):(\d+)\s+.*users:\(\(\"([^\"]+)\"", line)
        if not match:
            continue
        proto, address, port, process = match.groups()
        listeners.append({"proto": proto, "address": address, "port": int(port), "process": process})
    return listeners


def check_for(listener, host_bind):
    port, process = listener["port"], listener["process"]
    host = host_bind(listener["address"])
    if listener["proto"] == "tcp" and (port in HTTP_PORTS or process in UNIT_GUESSES and port in HTTP_PORTS):
        return {"name": "%s on %d" % (process, port), "kind": "http",
                "url": "http%s://%s:%d/" % ("s" if port in (443, 8443) else "", host, port),
                "expect_status": 200, "contains": "REPLACE_WITH_KNOWN_GOOD_TEXT"}
    spec = {"name": "%s on %d" % (process, port), "kind": "tcp", "host": host, "port": port}
    for unit_process, units in UNIT_GUESSES.items():
        if unit_process == process:
            spec["unit_guesses"] = units  # reviewer picks the right unit name for this distro
            break
    return spec


def host_bind(address):
    return "127.0.0.1" if address in ("0.0.0.0", "*", "[::]", "::") else address


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="config/services.local.json")
    args = p.parse_args()

    ss = shutil.which("ss")
    if not ss:
        print("REFUSED: `ss` not available (install iproute2/iproute2-ss)")
        return 2
    result = subprocess.run([ss, "-H", "-lntp"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, errors="replace", check=False)
    listeners = parse_ss(result.stdout)
    listeners = [x for x in listeners if x["proto"] == "tcp"]
    checks, seen = [], set()
    for listener in listeners:
        key = (listener["port"], host_bind(listener["address"]))
        if key in seen:
            continue
        seen.add(key)
        checks.append(check_for(listener, host_bind))
    checks.insert(0, {"name": "EDIT ME: generated %sZ (UTC) from live listeners; fill contains= "
                             "and unit names before trusting. TCP open is not 'app works'."
                      % dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%S"),
                      "kind": "tcp", "host": "127.0.0.1", "port": 22})
    path = Path(args.output)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        backup = path.with_suffix(".json.bak-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
        backup.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
        print("existing watchlist saved as " + backup.name)
    path.write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")

    print("=== SERVICE WATCHLIST GENERATOR ===")
    for check in checks:
        print("%-8s %-28s %s" % (check["kind"], check["name"], check.get("url") or "%s:%s" % (check.get("host"), check.get("port"))))
    print("wrote %s (%d checks)" % (path, len(checks)))
    print("NEXT: 1) fill every contains= with text from the real page  2) fix unit names per distro")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
