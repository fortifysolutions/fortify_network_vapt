import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"ldapsearch -x -H ldap://{shlex.quote(target)} -s base", verbose)
    anon = "namingcontexts" in out.lower() or "dn:" in out.lower()
    return {"raw": {"ldapsearch": out}, "parsed": {"anonymous_bind_or_info_leak": anon, "high_risk_count": 1 if anon else 0}}
