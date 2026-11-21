#!/usr/bin/env python3
"""Read-only persistence and suspicious-process triage. Findings are not malware verdicts.

2026 TRYOUT: use only after the official post-noon hunting transition and tool approval.
Keep all outputs within assigned infrastructure; honor protected accounts/whitelists.
Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time


def hostname():
    return socket.gethostname()


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


def hunt(args):
    out = new_run(args.output, "hunt")
    commands = {
        "sockets": ["ss", "-H", "-ntup"], "listeners": ["ss", "-H", "-lntup"],
        "processes": ["ps", "-eo", "pid,ppid,user,etimes,args", "--forest"],
        "deleted_open_files": ["lsof", "+L1"], "modules": ["lsmod"],
        "timers": ["systemctl", "list-timers", "--all", "--no-pager"],
        "units": ["systemctl", "list-unit-files", "--no-pager"],
        "auth_journal": ["journalctl", "--since", "-1 hour", "-u", "ssh", "-u", "sshd", "--no-pager", "-n", "500"],
        "audit_rules": ["auditctl", "-l"], "recent_failures": ["lastb", "-n", "50"],
        "capabilities": ["getcap", "-r", "/usr/bin", "/usr/sbin", "/usr/local"],
    }
    roots = args.paths or ["/etc", "/var/spool/cron", "/tmp", "/var/tmp", "/dev/shm", "/root/.ssh"]
    paths, errors, truncated = walk_files(roots, args.max_files)
    findings = []
    cutoff = time.time() - args.hours * 3600
    for value in paths:
        path = Path(value)
        try:
            st = path.lstat()
            reasons = []
            if st.st_mode & 0o6000:
                reasons.append("suid_or_sgid")
            if st.st_mode & 0o002:
                reasons.append("world_writable")
            if st.st_mtime >= cutoff:
                reasons.append("recent_mtime")
            if path.name in ("authorized_keys", "sshrc", "ld.so.preload"):
                reasons.append("review_auth_or_loader")
            if reasons:
                findings.append({"path": value, "reasons": reasons, "uid": st.st_uid,
                                 "mode": oct(st.st_mode & 0o7777), "mtime": st.st_mtime})
        except OSError as exc:
            errors.append({"path": value, "error": str(exc)})
    proc = []
    for item in Path("/proc").glob("[0-9]*/exe"):
        try:
            target = os.readlink(item)
            if "(deleted)" in target or target.startswith(("/tmp/", "/var/tmp/", "/dev/shm/", "/memfd:")):
                proc.append({"pid": item.parent.name, "exe": target,
                             "cmdline": read_text(item.parent / "cmdline")})
        except OSError:
            pass  # processes exit and /proc may restrict visibility
    persistence = ["/etc/crontab", "/etc/anacrontab", "/etc/rc.local", "/etc/ld.so.preload",
                   "/etc/sudoers", "/etc/ssh/sshd_config", "/proc/sys/kernel/tainted"]
    # Save bounded, textual persistence configuration; do not read shadow/private keys.
    for value in paths:
        path = Path(value)
        if path.is_symlink():
            continue
        if (value.startswith(("/etc/cron", "/var/spool/cron/", "/etc/systemd/system/",
                              "/etc/apt/apt.conf.d/", "/etc/pam.d/", "/etc/sudoers.d/"))
                or path.name == "authorized_keys") and path.is_file():
            persistence.append(value)
    report = {"time": utc(), "warning": "Triage leads, NOT malware verdicts. Local tools may be compromised.",
              "commands": {name: capture(cmd) for name, cmd in commands.items()},
              "file_findings": findings, "suspicious_executable_locations": proc,
              "persistence": {name: read_text(name, 65536) for name in sorted(set(persistence))},
              "files_examined": len(paths), "truncated": truncated, "errors": errors}
    save_json(out / "hunt.json", report)
    print("=== PERSISTENCE TRIAGE (leads, NOT verdicts) === host: %s" % socket.gethostname())
    print("file findings: %d | processes from tmp/deleted exe: %d | persistence configs captured: %d"
          % (len(findings), len(proc), len(report["persistence"])))
    listeners = report["commands"]["listeners"]
    if listeners["status"] == "ok":
        rows = [l for l in listeners["stdout"].splitlines() if l.strip()]
        tcp_rows = [l for l in rows if l.startswith("tcp")]
        udp_rows = [l for l in rows if l not in tcp_rows]
        print("LISTENERS (%d) - every port must be explainable:" % len(rows))
        for line in (tcp_rows + udp_rows)[:15]:
            print("  " + line)
    print("PERSISTENCE FILES CAPTURED:")
    for name in list(report["persistence"])[:15]:
        print("  " + name)
    for finding in findings[:15]:
        print("  %s  %s  (%s)" % (finding["path"], ",".join(finding["reasons"]), finding["mode"]))
    if len(findings) > 15:
        print("  ... +%d more in hunt.json" % (len(findings) - 15))
    for item in proc[:10]:
        print("  PROC pid=%s exe=%s" % (item["pid"], item["exe"]))
    preload = report["persistence"].get("/etc/ld.so.preload")
    if preload and preload.get("status") == "ok" and preload.get("text", "").strip():
        print("WARNING: /etc/ld.so.preload is non-empty - highest-priority check (chattr -i first if immutable)")
    print("detail: %s" % (out / "hunt.json"))


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
    p.add_argument("--paths", nargs="+", help="filesystem roots; default etc/cron/temp/root SSH")
    p.add_argument("--max-files", type=bounded_int(1, 1000000), default=25000)
    p.add_argument("--hours", type=positive_seconds, default=24.0)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return hunt(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
