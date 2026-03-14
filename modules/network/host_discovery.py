import ipaddress
import shlex
from core.executor import run_command


def _parse_fping(out: str):
    live = []
    unreachable = []
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if "is alive" in line and line[0].isdigit():
            live.append(line.split()[0])
        elif "ICMP Host Unreachable" in line:
            parts = line.split()
            if parts:
                unreachable.append(parts[-1])
    return list(dict.fromkeys(live)), list(dict.fromkeys(unreachable))


def _parse_nmap_sn(out: str):
    live = []
    unreachable = []
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            host = line.split()[-1].strip("()")
            live.append(host)
        if "Host is up" in line:
            continue
        if "0 hosts up" in line or "All 0 hosts up" in line:
            unreachable.append("all_scanned_hosts")
    return list(dict.fromkeys(live)), list(dict.fromkeys(unreachable))


def run(target, verbose=False):
    raw = {}
    live = []
    unreachable = []
    status = "ok"

    try:
        ipaddress.ip_network(target, strict=False)
        out, code = run_command(f"fping -a -g {shlex.quote(target)}", verbose, timeout=90)
        raw["fping"] = out
        live, unreachable = _parse_fping(out)
        if code != 0 and not live:
            status = "tool_error"
    except ValueError:
        out, code = run_command(f"nmap -sn {shlex.quote(target)}", verbose, timeout=90)
        raw["nmap_sn"] = out
        live, unreachable = _parse_nmap_sn(out)
        if not live:
            live = [target]
        if code != 0 and not live:
            status = "tool_error"

    return {
        "status": status,
        "raw": raw,
        "parsed": {
            "live_hosts": live,
            "unreachable_hosts": unreachable,
            "host_count": len(live),
            "unreachable_count": len(unreachable),
        },
    }
