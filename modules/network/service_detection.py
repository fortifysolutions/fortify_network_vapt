import re
import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"nmap -sV -Pn --open {shlex.quote(target)}", verbose)
    services = []
    for line in out.splitlines():
        m = re.search(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)$", line.strip())
        if m:
            services.append({"port": int(m.group(1)), "proto": m.group(2), "service": m.group(3), "version": m.group(4).strip()})
    return {"raw": {"nmap_sv": out}, "parsed": {"services": services}}
