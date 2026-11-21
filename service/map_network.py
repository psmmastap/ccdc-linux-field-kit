#!/usr/bin/env python3
"""Authorized, bounded TCP network mapping. No exploits, UDP scans or banners.

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import concurrent.futures
import csv
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import time


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


def parse_ports(value):
    ports = set()
    for part in value.split(","):
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            if not 1 <= lo <= hi <= 65535 or hi - lo + 1 > 1024:
                raise ValueError("use ascending ranges within 1..65535; at most 1024 ports")
            ports.update(range(lo, hi + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535 or len(ports) > 1024:
        raise ValueError("use 1..65535; at most 1024 ports per scan")
    return sorted(ports)


def scoped_targets(scope, requested, max_hosts):
    allowed = [ipaddress.ip_network(x, strict=True) for x in scope]
    targets = set()
    for value in requested:
        network = ipaddress.ip_network(value, strict=False)
        if not any(network.version == x.version and network.subnet_of(x) for x in allowed):
            raise ValueError("target outside authorized scope: " + value)
        # Bound BEFORE enumeration, particularly for accidental IPv6 /64 input.
        if network.num_addresses > max_hosts + 2:
            raise ValueError("target too large; narrow the CIDR")
        targets.update(str(x) for x in network.hosts())
        if len(targets) > max_hosts:
            raise ValueError("too many targets")
    return sorted(targets, key=lambda x: (ipaddress.ip_address(x).version, int(ipaddress.ip_address(x))))


def tcp_probe(host, port, timeout):
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"host": host, "port": port, "state": "open", "seconds": round(time.monotonic() - start, 4)}
    except OSError as exc:
        return {"host": host, "port": port, "state": "not_open", "error": str(exc)}


def scan(args):
    if not args.authorized:
        raise ValueError("active scanning requires --authorized and the event's permitted scope")
    hosts = scoped_targets(args.scope, args.target, args.max_hosts)
    ports = parse_ports(args.ports)
    if len(hosts) * len(ports) > 32768:
        raise ValueError("too many probes; split the scan")
    out = new_run(args.output, "scan")
    jobs = [(h, p, args.timeout) for h in hosts for p in ports]
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        results = list(pool.map(lambda x: tcp_probe(*x), jobs))
    save_json(out / "scan.json", {"time": utc(), "scope": args.scope, "results": results})
    with open(out / "open-ports.csv", "w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(["host", "port", "state"])
        for row in results:
            if row["state"] == "open":
                writer.writerow([row["host"], row["port"], row["state"]])
    opens = [r for r in results if r["state"] == "open"]
    print("=== NETWORK MAP (TCP connect only; no response does NOT mean host down) ===")
    print("probes: %d | open: %d | detail: %s" % (len(results), len(opens), out / "open-ports.csv"))
    by_host = {}
    for row in opens:
        by_host.setdefault(row["host"], []).append(row["port"])
    for host, ports in sorted(by_host.items()):
        print("  %-15s open: %s" % (host, ",".join(str(p) for p in sorted(ports))))


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
    p.add_argument("--authorized", action="store_true")
    p.add_argument("--scope", nargs="+", required=True, help="authorized CIDRs, not hostnames")
    p.add_argument("--target", nargs="+", required=True, help="IPs or CIDRs within scope")
    p.add_argument("--ports", default="22,53,80,443,445,3306,5432,8080,8443")
    p.add_argument("--max-hosts", type=bounded_int(1, 1024), default=256)
    p.add_argument("--workers", type=bounded_int(1, 32), default=8)
    p.add_argument("--timeout", type=positive_seconds, default=1.0)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return scan(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
