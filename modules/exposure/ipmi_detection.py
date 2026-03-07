import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"nmap -sU -p623 --script ipmi-version {shlex.quote(target)}", verbose)
    found = "ipmi" in out.lower() and "open" in out.lower()
    return {"raw": {"nmap_ipmi": out}, "parsed": {"ipmi_exposed": found, "high_risk_count": 1 if found else 0}}
