#!/usr/bin/env python3
"""Read-only Docker/container triage: containers, ports, mounts, suspicious config.

Works in both phases: morning (inventory, dependencies) and post-noon (triage).
Host-level hunting CANNOT see inside containers - run this on any Docker host.
Never starts/stops/execs anything.
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


def capture(argv, timeout=25):
    if not shutil.which(argv[0]):
        return {"status": "missing", "stdout": "", "stderr": "docker not installed"}
    try:
        p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           timeout=timeout, text=True, errors="replace", check=False)
        return {"status": "ok" if p.returncode == 0 else "error",
                "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except (subprocess.TimeoutExpired, OSError) as exc:
        return {"status": "error", "stdout": "", "stderr": str(exc)}


def parse_ps(text):
    """Parse `docker ps --format 'ID|Names|Image|Status|Ports'` output."""
    rows = []
    for line in text.splitlines():
        parts = line.split("|")
        if len(parts) == 5:
            rows.append({"container_id": parts[0], "names": parts[1], "image": parts[2],
                         "status": parts[3], "ports": parts[4]})
    return rows


def triage():
    findings, detail = [], {}
    ps = capture(["docker", "ps", "-a", "--format",
                  "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}"])
    detail["ps"] = ps
    containers = parse_ps(ps["stdout"]) if ps["status"] == "ok" else []
    detail["containers"] = containers
    if ps["status"] == "missing":
        findings.append("docker not installed on this host (skip unless services say otherwise)")
        return findings, detail
    if not containers:
        findings.append("no containers exist (docker present but unused)")
    for c in containers:
        name = c.get("names", c.get("container_id", "?"))
        ports = c.get("ports", "")
        if c.get("status", "").startswith("Up"):
            findings.append("RUNNING: %s (%s) ports: %s" % (name, c.get("image", "?"), ports or "none published"))

    inspect = capture(["docker", "inspect", "--format",
                       "{{.Name}}|{{json .HostConfig.PortBindings}}|{{json .Mounts}}|"
                       "{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.RestartPolicy.Name}}|{{.Config.Entrypoint}}|{{.Config.Cmd}}"]
                      + [c.get("names", c.get("container_id")) for c in containers])
    detail["inspect"] = inspect
    if inspect["status"] == "ok":
        for line in inspect["stdout"].splitlines():
            parts = line.split("|", 7)
            if len(parts) < 8:
                continue
            name, port_bindings, mounts, privileged, network, restart, entrypoint, cmd = parts
            notes = []
            if privileged == "true":
                notes.append("PRIVILEGED (near-host-equivalent - treat as part of the host)")
            if network in ("host",):
                notes.append("host network (ports do NOT traverse INPUT - firewall exceptions need FORWARD/direct handling)")
            if "docker.sock" in mounts:
                notes.append("mounts docker.sock (container can control Docker)")
            findings.append("CONFIG %s: net=%s restart=%s entrypoint=%s %s" %
                            (name.lstrip("/"), network, restart,
                             (entrypoint + " " + cmd).strip()[:80], " ".join("[" + n + "]" for n in notes)))
            findings.append("  mounts: " + mounts[:200])

    networks = capture(["docker", "network", "ls"])
    detail["networks"] = networks
    images = capture(["docker", "images", "--format", "{{.Repository}}:{{.Tag}} {{.CreatedSince}} {{.ID}}"])
    detail["images"] = images
    if images["status"] == "ok" and images["stdout"].strip():
        findings.append("images: " + " | ".join(images["stdout"].splitlines()[:8]))
    compose = capture(["docker", "compose", "ls"])
    detail["compose_projects"] = compose
    return findings, detail


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
    findings, detail = triage()
    (out_dir / ("docker-" + stamp + ".json")).write_text(
        json.dumps({"time": dt.datetime.now(dt.timezone.utc).isoformat() + "Z (UTC)",
                    "findings": findings, "detail": detail}, indent=2, default=str) + "\n", encoding="utf-8")

    print("=== DOCKER TRIAGE (read-only) ===")
    if findings:
        for f in findings:
            print(f)
    else:
        print("docker absent or nothing running")
    print("REMINDERS:")
    print("  - published ports traverse FORWARD/DNAT, NOT INPUT (host firewall rules on INPUT will not protect them)")
    print("  - `docker commit` excludes volumes; back up volume mounts separately")
    print("  - container filesystems are invisible to host hunts; docker exec + inspect inside as needed")
    print("detail: %s" % (out_dir / ("docker-" + stamp + ".json")))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(2)
    except KeyboardInterrupt:
        sys.exit(130)
