import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"nmap -Pn -p21,23,69,80,110,143,389,445 {shlex.quote(target)}", verbose)
    weak = [p for p in ["21/tcp", "23/tcp", "69/udp", "110/tcp", "143/tcp", "389/tcp"] if p in out and "open" in out]
    return {"raw": {"nmap": out}, "parsed": {"insecure_protocols": weak, "medium_risk_count": len(weak)}}
