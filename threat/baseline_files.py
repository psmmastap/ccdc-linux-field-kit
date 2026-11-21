#!/usr/bin/env python3
"""Hash selected paths and record permissions, owners and symlinks for later comparison.

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
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


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def walk_files(roots, max_files):
    """Do not follow symlinks or descend onto other filesystems. Report truncation."""
    entries, errors = [], []
    truncated = False
    for root in roots:
        root = Path(root)
        try:
            device = root.stat().st_dev
        except OSError as exc:
            errors.append({"path": str(root), "error": str(exc)})
            continue
        if root.is_symlink():
            candidates = [str(root)]
        elif root.is_file():
            candidates = [str(root)]
        else:
            def iterator():
                def onerror(exc):
                    errors.append({"path": exc.filename, "error": str(exc)})
                for parent, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
                    kept = []
                    for name in dirs:
                        path = Path(parent) / name
                        try:
                            if path.is_symlink():
                                yield str(path)
                            elif path.stat().st_dev == device:
                                kept.append(name)
                        except OSError as exc:
                            errors.append({"path": str(path), "error": str(exc)})
                    dirs[:] = sorted(kept)
                    for name in sorted(files):
                        yield str(Path(parent) / name)
            candidates = iterator()
        for path in candidates:
            if len(entries) >= max_files:
                truncated = True
                break
            entries.append(path)
        if truncated:
            break
    return entries, errors, truncated


def baseline(args):
    destination = Path(args.output).expanduser().resolve()
    roots = [Path(x).expanduser().resolve(strict=True) for x in args.paths]
    if any(root == destination or root in destination.parents for root in roots):
        raise ValueError("baseline output must be outside the scanned roots")
    out = new_run(destination, "baseline")
    files, errors, truncated = walk_files(roots, args.max_files)
    records = {}
    for value in files:
        path = Path(value)
        try:
            st = path.lstat()
            record = {"mode": st.st_mode & 0o7777, "uid": st.st_uid, "gid": st.st_gid}
            if path.is_symlink():
                record["symlink"] = os.readlink(path)
            elif path.is_file():
                record["size"] = st.st_size
                if st.st_size > args.max_bytes:
                    record["hash_status"] = "skipped_size_limit"
                else:
                    record["sha256"] = sha256(path)
            else:
                continue
            records[value] = record
        except OSError as exc:
            errors.append({"path": value, "error": str(exc)})
    save_json(out / "baseline.json", {"time": utc(), "roots": [str(x) for x in roots],
                                     "files": records, "errors": errors, "truncated": truncated})
    print("=== BASELINE ===")
    print("files recorded: %d | errors: %d | truncated: %s" % (len(records), len(errors), truncated))
    print("detail: %s" % (out / "baseline.json"))


def bounded_int(low, high):
    def parse(value):
        number = int(value)
        if not low <= number <= high:
            raise argparse.ArgumentTypeError("expected {}..{}".format(low, high))
        return number
    return parse


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence", help="private output directory OUTSIDE the scanned roots")
    p.add_argument("--paths", nargs="+", required=True)
    p.add_argument("--max-files", type=bounded_int(1, 1000000), default=25000)
    p.add_argument("--max-bytes", type=bounded_int(1, 1073741824), default=16777216)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return baseline(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
