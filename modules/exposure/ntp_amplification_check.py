import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"nmap -sU -p123 --script ntp-monlist {shlex.quote(target)}", verbose)
    vulnerable = "monlist" in out.lower() and "enabled" in out.lower()
    return {"raw": {"nmap_ntp": out}, "parsed": {"ntp_amplification_risk": vulnerable, "high_risk_count": 1 if vulnerable else 0}}
