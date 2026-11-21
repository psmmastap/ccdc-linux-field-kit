#!/usr/bin/env python3
"""Apply generated INPUT firewall rules WITH a timed, SSH-independent rollback.

Safety model (all mandatory):
  1. Saves current iptables/ip6tables state to /root/ccdc-firewall-<stamp>/.
  2. Writes a rollback script that restores the saved state.
  3. Schedules rollback OUTSIDE your SSH session (systemd-run when available,
     otherwise a detached setsid process) for --rollback-minutes (default 5).
  4. Applies rules with iptables-restore --noflush (does not touch other chains).
  5. You verify a NEW SSH login + scored services, then cancel with --confirm.
If you cannot reconnect, the rollback restores the old rules automatically.

Whitelist enforcement: every IP/CIDR in config/whitelist.txt gets an explicit
ACCEPT at the top of the chain so it can never be blocked (rule 3.6).

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import ipaddress
import os
from pathlib import Path
import shutil
import subprocess
import sys

CHAIN = "CCDC_INPUT"


def run(argv, timeout=30):
    p = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                       text=True, errors="replace", timeout=timeout, check=False)
    return p.returncode, p.stdout.strip(), p.stderr.strip()


def fail(message):
    print("REFUSED: " + message)
    sys.exit(2)


def load_whitelist_ips(path):
    nets = []
    try:
        for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
            entry = line.strip()
            if not entry or entry.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                pass  # account/process names are not firewall entries
    except OSError as exc:
        fail("cannot read whitelist %s: %s" % (path, exc))
    return nets


def build_final_rules(candidate_path, whitelist_nets, version):
    text = Path(candidate_path).read_text(encoding="utf-8")
    prefix = []
    for net in whitelist_nets:
        if net.version == version:
            prefix.append("-A %s -s %s -j ACCEPT" % (CHAIN, net))
    if not prefix:
        return text
    lines = text.splitlines()
    out = []
    for line in lines:
        # Insert whitelist ACCEPTs before the chain's first -A rule (after ":CHAIN ...")
        if out and line.startswith("-A " + CHAIN) and not any(x.startswith("-A " + CHAIN) for x in out):
            out.extend(prefix)
        out.append(line)
    if not any(x.startswith("-A " + CHAIN) for x in out):
        out.extend(prefix)
    return "\n".join(out) + "\n"


def schedule_rollback(rollback_script, seconds, stamp_dir):
    unit = "ccdc-rollback-" + stamp_dir.split("-")[-1]
    if shutil.which("systemd-run"):
        rc, out, err = run(["systemd-run", "--on-active=" + str(seconds),
                            "--unit=" + unit, "--description=CCDC firewall rollback",
                            "/bin/sh", str(rollback_script)])
        if rc == 0:
            return ("systemd", unit)
        print("note: systemd-run failed (%s); using detached fallback" % err)
    # Fallback: process fully detached from this session
    cmd = "exec %d sh %s" % (seconds, rollback_script)
    p = subprocess.Popen(["setsid", "/bin/sh", "-c", cmd],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, start_new_session=True)
    return ("setsid", str(p.pid))


def cancel_rollback(kind, handle):
    if kind == "systemd":
        run(["systemctl", "stop", handle + ".timer"])
        run(["systemctl", "stop", handle + ".service"])
    else:
        try:
            os.kill(int(handle), 15)
            return True
        except (ValueError, ProcessLookupError, PermissionError):
            return False
    return True


def main():
    os.umask(0o077)
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--rules4", help="candidate ipv4.rules from firewall_rules.py")
    p.add_argument("--rules6", help="candidate ipv6.rules from firewall_rules.py")
    p.add_argument("--whitelist", default="config/whitelist.txt")
    p.add_argument("--rollback-minutes", type=int, default=5)
    p.add_argument("--apply", action="store_true", help="save state, schedule rollback, apply (needs --approved too)")
    p.add_argument("--approved", action="store_true", help="confirm officials authorized this change")
    p.add_argument("--confirm", action="store_true", help="cancel pending rollback (run ONLY after verifying NEW SSH + services)")
    p.add_argument("--state-file", help="path to state file written by a previous apply (for --confirm)")
    args = p.parse_args()

    rc, _, err = run(["iptables", "--version"])
    if rc != 0:
        fail("iptables not usable on this host (%s). nft-native-only hosts need a different tool." % err)
    rc, _, err = run(["iptables-restore", "--test", "/dev/null"])
    if rc != 0 and "invalid" not in err.lower():
        print("note: iptables-restore --test on /dev/null reported: %s (continuing; verification happens per-ruleset)" % err)

    if args.confirm:
        if not args.state_file or not Path(args.state_file).is_file():
            fail("--confirm needs --state-file pointing at the apply's state file")
        data = Path(args.state_file).read_text(encoding="utf-8").splitlines()
        kind, handle = data[0].split("=", 1)
        ok = cancel_rollback(kind, handle)
        print(("rollback cancelled - rules stay in place" if ok else
               "could not cancel rollback (%s %s); let it fire - it just re-applies the saved state" % (kind, handle)))
        return 0 if ok else 1

    if not args.rules4 and not args.rules6:
        fail("nothing to do: give --rules4 and/or --rules6 (generated by firewall_rules.py)")
    if not args.apply:
        print("DRY RUN (no --apply). Would:")
        if args.rules4:
            print("  apply %s via iptables-restore --noflush" % args.rules4)
        if args.rules6:
            print("  apply %s via ip6tables-restore --noflush" % args.rules6)
        print("  schedule rollback in %d minutes (survives SSH death)" % args.rollback_minutes)
        print("Re-run with --apply --approved when you are on a console-tested plan.")
        return 0
    if not args.approved:
        fail("--apply requires --approved")

    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    state_dir = Path("/root/ccdc-firewall-" + stamp)
    state_dir.mkdir(mode=0o700)
    (state_dir / "v4-before.rules").write_text(run(["iptables-save"])[1] + "\n", encoding="utf-8")
    (state_dir / "v6-before.rules").write_text(run(["ip6tables-save"])[1] + "\n", encoding="utf-8")

    whitelist_nets = load_whitelist_ips(args.whitelist)
    rc4, _, _ = run(["iptables", "-S", CHAIN])
    if rc4 == 0:
        fail("chain %s already exists (re-apply would stack rules). Cancel it first: iptables -D INPUT -j %s; iptables -X %s" % (CHAIN, CHAIN, CHAIN))

    for version, candidate, out_name, restore in (
            (4, args.rules4, "v4-candidate.rules", "iptables-restore"),
            (6, args.rules6, "v6-candidate.rules", "ip6tables-restore")):
        if candidate:
            final = build_final_rules(candidate, whitelist_nets, version)
            (state_dir / out_name).write_text(final, encoding="utf-8")
            rc, _, err = run([restore, "--test", str(state_dir / out_name)])
            if rc != 0:
                fail("candidate ruleset failed iptables-restore --test: %s" % err)

    rollback = state_dir / "rollback.sh"
    restore_bins = []
    for restore in ("iptables-restore", "ip6tables-restore"):
        located = shutil.which(restore)
        if located:
            restore_bins.append((restore, located))
    restore_lines = []
    if args.rules4:
        restore_lines.append("%s < %s/v4-before.rules" % (dict(restore_bins)["iptables-restore"], state_dir))
    if args.rules6:
        restore_lines.append("%s < %s/v6-before.rules" % (dict(restore_bins)["ip6tables-restore"], state_dir))
    rollback.write_text(
        "#!/bin/sh\n# Auto-generated rollback for CCDC firewall apply %s\n%s\n" % (stamp, "\n".join(restore_lines)),
        encoding="utf-8")
    rollback.chmod(0o700)

    kind, handle = schedule_rollback(rollback, args.rollback_minutes * 60, stamp)
    (state_dir / "state.txt").write_text("kind=%s\nhandle=%s\n" % (kind, handle), encoding="utf-8")

    print("saved pre-change state + rollback in %s" % state_dir)
    print("rollback scheduled via %s (%s) in %d minutes" % (kind, handle, args.rollback_minutes))
    for candidate, out_name, restore in ((args.rules4, "v4-candidate.rules", "iptables-restore"),
                                         (args.rules6, "v6-candidate.rules", "ip6tables-restore")):
        if candidate:
            rc, _, err = run([restore, "--noflush", str(state_dir / out_name)])
            if rc != 0:
                print("APPLY FAILED (%s): %s" % (restore, err))
                print("rollback will restore the old rules automatically in %d minutes." % args.rollback_minutes)
                return 1
            print("applied %s" % out_name)
    print()
    print("NOW, within the rollback window:")
    print("  1. open a NEW SSH session (existing sessions surviving proves nothing)")
    print("  2. verify scored services and whitelisted traffic")
    print("  3. cancel the rollback:  python3 %s --confirm --state-file %s/state.txt" % (Path(__file__).name, state_dir))
    print("If you cannot reconnect, do nothing - rollback fires automatically.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
    except (OSError, ValueError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        sys.exit(2)
