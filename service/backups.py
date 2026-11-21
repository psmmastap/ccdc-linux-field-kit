#!/usr/bin/env python3
"""Verified GNU tar file backups with Linux metadata. NOT a live database backup.

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import shutil
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


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def backup(args):
    """GNU tar preserves numeric owners, ACLs, xattrs and SELinux labels."""
    sources = [Path(x).expanduser().resolve(strict=True) for x in args.paths]
    # Resolve all ancestors, including symlinks, before comparing destination.
    destination = Path(args.output).expanduser().resolve()
    for source in sources:
        if not source.is_dir() and not source.is_file():
            raise ValueError("source must be a regular file or directory: " + str(source))
        if source == Path(source.anchor):
            raise ValueError("whole-filesystem backups not supported; select directories")
        if source == destination or source in destination.parents:
            raise ValueError("backup output must not be inside any source")
        if any(other != source and other in source.parents for other in sources):
            raise ValueError("overlapping sources; select only the parent")
    version = capture(["tar", "--version"])
    if version["status"] != "ok" or "GNU tar" not in version["stdout"]:
        raise ValueError("backup requires GNU tar for Linux ownership/ACL/xattr preservation")
    out = new_run(destination, "backup")
    archive = out / "files.tar.gz"
    manifest = {"time": utc(), "sources": [str(x) for x in sources], "status": "incomplete",
                "warning": "Live files are not an application-consistent database backup. No automatic restore."}
    save_json(out / "manifest.json", manifest)
    cmd = ["tar", "--create", "--gzip", "--file", str(archive), "--numeric-owner",
           "--acls", "--xattrs", "--selinux", "--one-file-system", "--directory", "/", "--"]
    cmd.extend(str(x).lstrip("/") for x in sources)
    # No timeout: a large backup may legitimately take a long time. Never mark rc=1 successful.
    with open(out / "tar.stderr", "w", encoding="utf-8") as err:
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=err, check=False)
    manifest["tar_returncode"] = result.returncode
    if result.returncode != 0:
        save_json(out / "manifest.json", manifest)
        raise ValueError("backup incomplete; preserve and inspect " + str(out))
    # Stream the full listing to disk, not RAM; listing verifies gzip/tar readability.
    with open(out / "archive-list.txt", "w", encoding="utf-8") as listing, open(out / "verify.stderr", "w", encoding="utf-8") as err:
        check = subprocess.run(["tar", "-tzf", str(archive)], stdout=listing, stderr=err, check=False)
    if check.returncode != 0:
        raise ValueError("archive verification failed: " + str(out))
    manifest.update(status="verified-readable", sha256=sha256(archive), bytes=archive.stat().st_size)
    save_json(out / "manifest.json", manifest)
    (out / "SHA256SUMS").write_text(manifest["sha256"] + "  files.tar.gz\n", encoding="utf-8")
    print("BACKUP VERIFIED-READABLE: %.1f MiB  sha256=%s..." % (manifest["bytes"] / 1048576, manifest["sha256"][:16]))
    print(out)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence", help="private destination OUTSIDE all source directories")
    p.add_argument("--paths", nargs="+", required=True)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return backup(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
