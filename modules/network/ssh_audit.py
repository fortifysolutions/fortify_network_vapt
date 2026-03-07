import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"nmap --script ssh2-enum-algos,ssh-auth-methods -p22 {shlex.quote(target)}", verbose)
    weak = "diffie-hellman-group1-sha1" in out.lower() or "password" in out.lower()
    return {"raw": {"nmap_ssh": out}, "parsed": {"weak_ssh_policy": weak, "medium_risk_count": 1 if weak else 0}}
