#!/usr/bin/env python3
"""Generate candidate IPv4 and IPv6 iptables INPUT rules. NEVER applies rules.

Standalone script. Python 3.8+, standard library only.
"""
import argparse
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import sys
import tempfile


def load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def new_run(base, kind):
    base = Path(base).expanduser()
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = Path(tempfile.mkdtemp(prefix=kind + "-" + dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ-"), dir=str(base)))
    path.chmod(0o700)
    return path


def render_firewall(config, version):
    chain = "CCDC_INPUT"
    lines = ["*filter", ":" + chain + " - [0:0]", "-A " + chain + " -i lo -j ACCEPT",
             "-A " + chain + " -m conntrack --ctstate INVALID -j DROP",
             "-A " + chain + " -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
             "-A " + chain + (" -p icmp" if version == 4 else " -p ipv6-icmp") + " -j ACCEPT"]
    for rule in config["allow"]:
        if rule["protocol"] not in ("tcp", "udp"):
            raise ValueError("firewall protocol must be tcp or udp")
        port = rule["port"]
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("firewall port must be integer 1..65535")
        if not rule.get("sources"):
            raise ValueError("each allow rule needs explicit source CIDRs")
        for source in rule["sources"]:
            network = ipaddress.ip_network(source, strict=True)
            if network.version == version:
                lines.append("-A {} -s {} -p {} --dport {} -m conntrack --ctstate NEW -j ACCEPT".format(chain, network, rule["protocol"], port))
    lines.extend(["-A " + chain + " -j DROP", "-I INPUT 1 -j " + chain, "COMMIT", ""])
    return "\n".join(lines)


def firewall(args):
    config = load_json(args.config)
    if config.get("reviewed_for_this_host") is not True:
        raise ValueError("fill in the host's real dependencies and set reviewed_for_this_host to true; generation only")
    rules4, rules6 = render_firewall(config, 4), render_firewall(config, 6)
    out = new_run(args.output, "firewall")
    (out / "ipv4.rules").write_text(rules4, encoding="ascii")
    (out / "ipv6.rules").write_text(rules6, encoding="ascii")
    (out / "WARNING.txt").write_text(
        "GENERATION ONLY. These are candidate host INPUT rules, not a universal policy.\n"
        "APPLY THEM ONLY VIA: python3 service/firewall_apply.py --rules4 ipv4.rules --apply --approved\n"
        "(it saves pre-change state, schedules an SSH-independent timed rollback, and force-allows\n"
        "every IP/CIDR in config/whitelist.txt). Manual apply needs iptables-restore/ip6tables-restore\n"
        "--noflush; the CCDC_INPUT chain must NOT exist.\n"
        "Do not apply on a router/container host or alongside firewalld/ufw/native nft rules without redesign.\n"
        "OUTPUT and FORWARD remain unchanged. Existing INPUT rules are bypassed by a first-position jump.\n"
        "Validate scoring/dependencies first. Do not make persistent before testing NEW SSH + scored transactions.\n",
        encoding="utf-8")
    print(out)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", default="./evidence", help="private local output directory")
    p.add_argument("--config", required=True)
    return p


def main():
    os.umask(0o077)
    args = parser().parse_args()
    try:
        return firewall(args) or 0
    except (ValueError, KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("interrupted; partial evidence may remain", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
