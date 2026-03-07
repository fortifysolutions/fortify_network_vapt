import shlex
from core.executor import run_command


def run(target, verbose=False):
    tr, _ = run_command(f"traceroute {shlex.quote(target)}", verbose)
    hops = [x for x in tr.splitlines() if x.strip() and x[0].isdigit()]
    return {"raw": {"traceroute": tr}, "parsed": {"hop_count": len(hops), "medium_risk_count": 1 if len(hops) <= 2 else 0}}
