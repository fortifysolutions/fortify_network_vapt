import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"nmap -O -Pn {shlex.quote(target)}", verbose)
    return {"raw": {"nmap_os": out}, "parsed": {"os_guess_available": "OS details" in out or "Running:" in out}}
