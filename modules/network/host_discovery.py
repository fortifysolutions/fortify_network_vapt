import ipaddress
import shlex
from core.executor import run_command


def _extract_hosts(out):
    hosts = []
    for line in out.splitlines():
        line = line.strip()
        if line and line[0].isdigit() and "is alive" in line:
            hosts.append(line.split()[0])
        if "Nmap scan report for" in line:
            hosts.append(line.split()[-1].strip("()"))
    return list(dict.fromkeys(hosts))


def run(target, verbose=False):
    hosts = []
    raw = {}
    try:
        ipaddress.ip_network(target, strict=False)
        out, _ = run_command(f"fping -a -g {shlex.quote(target)}", verbose, timeout=90)
        raw["fping"] = out
        hosts = _extract_hosts(out)
    except ValueError:
        out, _ = run_command(f"nmap -sn {shlex.quote(target)}", verbose, timeout=90)
        raw["nmap_sn"] = out
        hosts = _extract_hosts(out)
        if not hosts:
            hosts = [target]
    return {"raw": raw, "parsed": {"live_hosts": hosts, "host_count": len(hosts)}}
