#!/usr/bin/env python3
"""Compare two baseline.json files. Never changes the files being assessed.

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import sys
import tempfile


def save_json(path, data):
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def new_run(base, kind):
    base = Path(base).expanduser()
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = Path(tempfile.mkdtemp(prefix=kind + "-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=str(base)))
    path.chmod(0o700)
    return path


def compare(args):
    before, after = load_json(args.before), load_json(args.after)
    if before["roots"] != after["roots"]:
        raise ValueError("baseline roots differ; compare the same paths")
    a, b = before["files"], after["files"]
    out = new_run(args.output, "diff")
    changes = {"added": sorted(set(b) - set(a)), "removed": sorted(set(a) - set(b)),
               "changed": [{"path": p, "before": a[p], "after": b[p]} for p in sorted(set(a) & set(b)) if a[p] != b[p]],
               "incomplete": any(x.get("truncated") or x.get("errors") for x in (before, after)),
               "warning": "No changes is not proof of integrity; skipped hashes, ACLs and xattrs are not compared."}
    save_json(out / "diff.json", changes)
    print("=== BASELINE DIFF ===")
    print("added: %d | removed: %d | changed: %d | incomplete scan: %s"
          % (len(changes["added"]), len(changes["removed"]), len(changes["changed"]), changes["incomplete"]))
    for path in changes["added"][:10]:
        print("  ADDED   " + path)
    for path in changes["removed"][:10]:
        print("  REMOVED " + path)
    for item in changes["changed"][:10]:
        print("  CHANGED " + item["path"])
    if len(changes["added"]) + len(changes["removed"]) + len(changes["changed"]) > 30:
        print("  ... full list in diff.json")
    print("detail: %s" % (out / "diff.json"))


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence", help="private local output directory")
    p.add_argument("--before", required=True)
    p.add_argument("--after", required=True)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return compare(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
