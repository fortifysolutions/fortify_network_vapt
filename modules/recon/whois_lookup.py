import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, code = run_command(f"whois {shlex.quote(target)}", verbose)
    return {"raw": {"whois": out}, "parsed": {"success": code == 0}, "error": None if code == 0 else "whois failed"}
