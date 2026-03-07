import re
import shlex
from core.executor import run_command


def run(target, verbose=False):
    safe = shlex.quote(target)
    ns_out, _ = run_command(f"dig +short NS {safe}", verbose)
    ns_hosts = [re.sub(r'\.$', '', x.strip().split()[-1]) for x in ns_out.splitlines() if x.strip()]
    results = {}
    allowed = []
    for ns in ns_hosts:
        zt, code = run_command(f"dig AXFR {safe} @{shlex.quote(ns)}", verbose)
        results[ns] = zt
        if code == 0 and "Transfer failed" not in zt and "connection timed out" not in zt.lower():
            if "\tIN\t" in zt:
                allowed.append(ns)
    return {
        "raw": {"zone_transfer": results},
        "parsed": {"zone_transfer_allowed": len(allowed) > 0, "vulnerable_nameservers": allowed, "high_risk_count": len(allowed)}
    }
