#!/usr/bin/env python3
"""Read-only Linux environment inventory: OS, accounts, services, containers and networking.

Includes security-related collection: confirm permitted phase/official approval for tryouts.
Keep all reports within assigned infrastructure. Do not use to evade the morning hunting ban.
Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import stat
import subprocess
import sys
import tempfile


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


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


def read_text(path, limit=262144):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return {"status": "error", "error": "not a regular file; refusing device/FIFO/socket"}
            with os.fdopen(fd, encoding="utf-8", errors="replace", closefd=False) as stream:
                text = stream.read(limit + 1)
        finally:
            os.close(fd)
        return {"status": "ok", "text": text[:limit], "truncated": len(text) > limit}
    except OSError as exc:
        return {"status": "error", "error": str(exc)}


def inventory(args):
    commands = {
        "kernel": ["uname", "-a"], "identity": ["id"],
        "addresses": ["ip", "-j", "address"], "routes": ["ip", "-j", "route", "show", "table", "all"],
        "routes_v6": ["ip", "-j", "-6", "route", "show", "table", "all"],
        "neighbors": ["ip", "-j", "neigh"], "listeners": ["ss", "-H", "-lntup"],
        "connections": ["ss", "-H", "-ntup"], "processes": ["ps", "-eo", "pid,ppid,user,lstart,args", "--forest"],
        "filesystems": ["findmnt", "-J"], "disk": ["df", "-hT"],
        "services": ["systemctl", "list-units", "--all", "--type=service", "--no-pager"],
        "enabled_units": ["systemctl", "list-unit-files", "--no-pager"],
        "timers": ["systemctl", "list-timers", "--all", "--no-pager"],
        "openrc": ["rc-status", "--all"], "users": ["getent", "passwd"], "groups": ["getent", "group"],
        "logins": ["last", "-n", "30"], "firewall_v4": ["iptables-save"],
        "firewall_v6": ["ip6tables-save"], "nftables": ["nft", "list", "ruleset"],
        "firewalld": ["firewall-cmd", "--list-all-zones"], "ufw": ["ufw", "status", "verbose"],
        "containers": ["docker", "ps", "--no-trunc"], "podman": ["podman", "ps", "--no-trunc"],
        "container_networks": ["docker", "network", "ls"],
        "packages_deb": ["dpkg-query", "-W"], "packages_rpm": ["rpm", "-qa"],
        "packages_apk": ["apk", "info", "-v"], "capabilities": ["getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local"],
        "selinux": ["getenforce"], "apparmor": ["aa-status"], "time_sync": ["timedatectl"],
    }
    files = ["/etc/os-release", "/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf",
             "/etc/fstab", "/etc/ssh/sshd_config", "/etc/ld.so.preload", "/proc/sys/kernel/tainted"]
    out = new_run(args.output, "inventory")
    report = {"time": utc(), "hostname": socket.gethostname(), "platform": platform.platform(),
              "root": hasattr(os, "geteuid") and os.geteuid() == 0,
              "commands": {name: capture(cmd) for name, cmd in commands.items()},
              "files": {name: read_text(name) for name in files}}
    save_json(out / "inventory.json", report)
    # Concise day-of summary: the details are in inventory.json, this is the 10-second read.
    print("=== ENVIRONMENT SNAPSHOT (read-only) === host: %s" % socket.gethostname())
    os_release = report["files"]["/etc/os-release"]
    if os_release["status"] == "ok":
        for line in os_release["text"].splitlines():
            if line.startswith(("PRETTY_NAME=", "ID=")):
                print(line)

    addresses = report["commands"]["addresses"]
    if addresses["status"] == "ok":
        try:
            for iface in json.loads(addresses["stdout"]):
                addrs = " ".join(x.get("local", "") for x in iface.get("addr_info", []))
                if addrs or iface.get("ifname") != "lo":
                    print("  %-10s %s" % (iface.get("ifname", "?"), addrs))
        except (ValueError, KeyError):
            pass
    routes = report["commands"]["routes"]
    if routes["status"] == "ok":
        try:
            shown = 0
            for route in json.loads(routes["stdout"]):
                if route.get("table") not in (None, "main"):
                    continue
                parts = [route.get("dst", "?")]
                if route.get("gateway"):
                    parts.append("via %s" % route["gateway"])
                parts.append("dev %s" % route.get("dev", "?"))
                print("  route: " + " ".join(parts))
                shown += 1
                if shown >= 6:
                    break
        except (ValueError, KeyError, TypeError):
            pass

    listeners = report["commands"]["listeners"]
    if listeners["status"] == "ok":
        rows = [l for l in listeners["stdout"].splitlines() if l.strip()]
        tcp_rows = [l for l in rows if l.startswith("tcp")]
        udp_rows = [l for l in rows if l not in tcp_rows]
        print("LISTENING (%d) - every port must be explainable:" % len(rows))
        for line in (tcp_rows + udp_rows)[:15]:
            print("  " + line)
        if len(rows) > 15:
            print("  ... +%d more (rerun: ss -lntp)" % (len(rows) - 15))
    connections = report["commands"]["connections"]
    if connections["status"] == "ok":
        rows = [l for l in connections["stdout"].splitlines() if l.strip()]
        print("ESTABLISHED (%d) - who are we talking to:" % len(rows))
        for line in rows[:10]:
            print("  " + line)
        if len(rows) > 10:
            print("  ... +%d more (rerun: ss -ntp)" % (len(rows) - 10))
    tainted = report["files"]["/proc/sys/kernel/tainted"]
    if tainted["status"] == "ok" and tainted["text"].strip() not in ("0", ""):
        print("KERNEL TAINTED: %s (non-zero = module loaded/crashed; note it)" % tainted["text"].strip())
    time_sync = report["commands"]["time_sync"]
    if time_sync["status"] == "ok" and "NTP service: active" not in time_sync["stdout"]:
        line = next((l for l in time_sync["stdout"].splitlines() if "NTP" in l or "synchronized" in l), "")
        print("TIME SYNC: %s (drift breaks log correlation and scoring - fix if inactive)" % line.strip() or "not synchronized")
    preload = report["files"]["/etc/ld.so.preload"]
    if preload["status"] == "ok" and preload["text"].strip():
        print("WARNING: /etc/ld.so.preload EXISTS and is non-empty - review immediately")
    print("detail: %s" % (out / "inventory.json"))


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence", help="private local output directory")
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return inventory(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
