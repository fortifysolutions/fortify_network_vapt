import shlex
from core.executor import run_command


def run(target, verbose=False):
    safe = shlex.quote(target)
    a, _ = run_command(f"dig +short A {safe}", verbose)
    mx, _ = run_command(f"dig +short MX {safe}", verbose)
    ns, _ = run_command(f"dig +short NS {safe}", verbose)
    ptr, _ = run_command(f"host {safe}", verbose)
    return {
        "raw": {"a": a, "mx": mx, "ns": ns, "host": ptr},
        "parsed": {
            "a_records": [x for x in a.splitlines() if x.strip()],
            "mx_records": [x for x in mx.splitlines() if x.strip()],
            "ns_records": [x for x in ns.splitlines() if x.strip()],
        }
    }
