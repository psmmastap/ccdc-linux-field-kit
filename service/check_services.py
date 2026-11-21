#!/usr/bin/env python3
"""TCP, HTTP and systemd health checks. Never restarts services.

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def new_run(base, kind):
    base = Path(base).expanduser()
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = Path(tempfile.mkdtemp(prefix=kind + "-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=str(base)))
    path.chmod(0o700)
    return path


def capture(argv, timeout=20):
    """Never invoke a shell; retain errors instead of calling absence healthy."""
    if not shutil.which(argv[0]):
        return {"argv": argv, "status": "missing", "stdout": "", "stderr": "command not installed"}
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True, errors="replace", check=False)
        return {"argv": argv, "status": "ok" if p.returncode == 0 else "error",
                "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except subprocess.TimeoutExpired:
        return {"argv": argv, "status": "timeout", "stdout": "", "stderr": "command timed out"}
    except OSError as exc:
        return {"argv": argv, "status": "error", "stdout": "", "stderr": str(exc)}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def service_probe(spec, timeout):
    if not isinstance(spec, dict):
        return {"name": "invalid check", "kind": None, "ok": False,
                "detail": "each check must be a JSON object", "seconds": 0}
    start = time.monotonic()
    kind = spec.get("kind")
    detail = ""
    ok = False
    try:
        if kind == "tcp":
            port = int(spec["port"])
            if not 1 <= port <= 65535:
                raise ValueError("invalid port")
            with socket.create_connection((spec["host"], port), timeout=timeout):
                ok, detail = True, "TCP connect only; not an application login test"
        elif kind == "http":
            url = spec["url"]
            parsed = urllib.parse.urlsplit(url)
            if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
                raise ValueError("use HTTP(S), without embedded credentials")
            # Ignore ambient proxies and do not follow redirects to an unapproved destination.
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            req = urllib.request.Request(url, headers={"User-Agent": "CCDC-healthcheck/1.0"})
            try:
                response = opener.open(req, timeout=timeout)
            except urllib.error.HTTPError as exc:
                response = exc
            with response:
                body = response.read(1024 * 1024)
                expected = spec.get("expect_status", 200)
                ok = response.code == expected
                if "contains" in spec:
                    ok = ok and spec["contains"] in body.decode("utf-8", errors="replace")
                detail = "HTTP " + str(response.code) + "; body check limited to 1 MiB"
        elif kind == "systemd":
            unit = spec["unit"]
            if not re.fullmatch(r"[A-Za-z0-9_.@:-]+", unit) or unit.startswith("-"):
                raise ValueError("invalid unit name")
            result = capture(["systemctl", "is-active", "--", unit], timeout=timeout)
            ok = result["status"] == "ok" and result["stdout"].strip() == "active"
            detail = result["status"] + ": " + result["stdout"].strip() + " " + result["stderr"].strip()
        else:
            raise ValueError("kind must be tcp, http or systemd")
    except (OSError, ValueError, TypeError, KeyError, urllib.error.URLError) as exc:
        detail = str(exc)
    return {"name": spec.get("name", "unnamed"), "kind": kind, "ok": ok,
            "detail": detail, "seconds": round(time.monotonic() - start, 4)}


def services(args):
    config = load_json(args.config)
    if not isinstance(config, list) or not config:
        raise ValueError("services config must be a nonempty list")
    out = new_run(args.output, "services")
    failed = False
    for iteration in range(args.count):
        rows = [service_probe(x, args.timeout) for x in config]
        failed = failed or any(not x["ok"] for x in rows)
        with open(out / "checks.jsonl", "a", encoding="utf-8") as stream:
            stream.write(json.dumps({"time": utc(), "checks": rows}) + "\n")
        for row in rows:
            print(("OK   " if row["ok"] else "FAIL ") + row["name"] + ": " + row["detail"])
        if iteration + 1 < args.count:
            time.sleep(args.interval)
    print("last pass: %d/%d checks OK" % (sum(1 for x in rows if x["ok"]), len(rows)))
    print(out)
    return 1 if failed else 0


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("expected {}..{}".format(low, high))
        return number
    return parse


def positive_seconds(value):
    number = float(value)
    if not 0.05 <= number <= 3600:
        raise argparse.ArgumentTypeError("expected 0.05..3600 seconds")
    return number


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence", help="private local output directory")
    p.add_argument("--config", required=True)
    p.add_argument("--count", type=bounded_int(1, 10000), default=1)
    p.add_argument("--interval", type=positive_seconds, default=30.0)
    p.add_argument("--timeout", type=positive_seconds, default=3.0)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return services(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
