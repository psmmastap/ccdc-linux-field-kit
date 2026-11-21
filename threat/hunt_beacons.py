#!/usr/bin/env python3
"""Rank connection-start CSV by timing regularity. Offline heuristic, not malware detection proof.

2026 TRYOUT: use only after the official post-noon hunting transition and tool approval.
Never export competition telemetry to your personal machine or external services.
Standalone script. Python 3.8+, standard library only.
"""
import argparse
import csv
import datetime as dt
import json
import os
from pathlib import Path
import statistics
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


def beacon_rank(events, minimum):
    groups = {}
    for event in events:
        key = tuple(str(event.get(k, "")) for k in ("src", "dst", "port", "proto"))
        groups.setdefault(key, set()).add(float(event["timestamp"]))
    rows = []
    for key, values in groups.items():
        times = sorted(values)
        if len(times) < minimum:
            continue
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean
        rows.append({"src": key[0], "dst": key[1], "port": key[2], "proto": key[3],
                     "events": len(times), "mean_gap_seconds": round(mean, 3),
                     "gap_cv": round(cv, 4), "duration_seconds": round(times[-1] - times[0], 3),
                     "lead": "regular_timing" if cv <= 0.2 else "irregular"})
    return sorted(rows, key=lambda x: (x["gap_cv"], -x["events"]))


def beacons(args):
    events = []
    with open(args.input, encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"timestamp", "src", "dst", "port", "proto"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError("CSV needs timestamp,src,dst,port,proto; timestamp is epoch seconds")
        for row in reader:
            stamp = float(row["timestamp"])
            if not 0 <= stamp < 1e12:
                raise ValueError("invalid epoch timestamp")
            events.append(row)
            if len(events) > 1000000:
                raise ValueError("split inputs larger than one million events")
    out = new_run(args.output, "beacons")
    candidates = beacon_rank(events, args.minimum)
    save_json(out / "beacons.json", {"time": utc(), "candidates": candidates,
              "warning": "Timing heuristic only. Monitoring, DNS, NTP and scoring also repeat; jittered C2 may not rank. Use connection starts, not every packet."})
    print("=== BEACON TIMING (heuristic leads) ===")
    print("event groups analyzed: %d | regular-timing candidates: %d" % (
        len(candidates), sum(1 for c in candidates if c["lead"] == "regular_timing")))
    for row in candidates[:10]:
        print("  cv=%.2f  %s -> %s:%s (%s, %d events, ~%ss gap)  %s"
              % (row["gap_cv"], row["src"], row["dst"], row["port"], row["proto"], row["events"],
                 row["mean_gap_seconds"], row["lead"]))
    print("detail: %s" % (out / "beacons.json"))


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("expected {}..{}".format(low, high))
        return number
    return parse


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence", help="private local output directory")
    p.add_argument("--input", required=True)
    p.add_argument("--minimum", type=bounded_int(4, 100000), default=6)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return beacons(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
