import re
import shlex
from core.config import WELL_KNOWN_PORTS
from core.executor import run_command

HIGH_RISK_PORTS = {23, 21, 3389, 2375, 445, 623, 9100, 27017, 6379, 6443}
MEDIUM_RISK_PORTS = {21, 25, 110, 143, 389, 5900, 5901, 8080, 8443}


def run(target, verbose=False):
    out, code = run_command(f"nmap -Pn -T4 --top-ports 200 --open {shlex.quote(target)}", verbose)
    ports = []
    high_count = 0
    medium_count = 0

    for line in out.splitlines():
        m = re.search(r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)?\s*(.*)$", line.strip())
        if not m:
            continue
        p = int(m.group(1))
        state = m.group(3)
        service = (m.group(4) or "").strip()
        version = (m.group(5) or "").strip()
        risk = "low"
        if p in HIGH_RISK_PORTS:
            risk = "high"
            high_count += 1
        elif p in MEDIUM_RISK_PORTS:
            risk = "medium"
            medium_count += 1

        ports.append({
            "port": p,
            "proto": m.group(2),
            "state": state,
            "service_hint": service or WELL_KNOWN_PORTS.get(p, "unknown"),
            "version": version,
            "risk": risk,
        })

    return {
        "status": "ok" if code == 0 else "tool_error",
        "raw": {"nmap": out},
        "parsed": {
            "ports": ports,
            "high_risk_count": high_count,
            "medium_risk_count": medium_count,
            "exit_code": code,
        },
    }
