import re
import shlex
from core.config import WELL_KNOWN_PORTS
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"nmap -Pn -T4 --top-ports 200 --open {shlex.quote(target)}", verbose)
    ports = []
    for line in out.splitlines():
        m = re.search(r"^(\d+)/tcp\s+open", line.strip())
        if m:
            p = int(m.group(1))
            ports.append({"port": p, "service_hint": WELL_KNOWN_PORTS.get(p, "unknown")})
    risky = [p for p in ports if p["port"] in [23, 21, 3389, 2375, 445, 623, 9100, 27017, 6379, 6443]]
    return {"raw": {"nmap": out}, "parsed": {"open_ports": ports, "high_risk_ports": risky, "high_risk_count": len(risky)}}
