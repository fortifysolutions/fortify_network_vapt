import shlex
from core.executor import run_command


def run(target, verbose=False, config=None):
    cfg = config or {}
    cookie = (cfg.get("cookie") or "").strip()
    auth_header = (cfg.get("auth_header") or "").strip()

    nse, _ = run_command(f"nmap --script vuln -Pn {shlex.quote(target)}", verbose, timeout=300)
    nuclei_cmd = f"nuclei -target {shlex.quote(target)} -ni -silent"
    if cookie:
        nuclei_cmd += f" -H {shlex.quote(f'Cookie: {cookie}')}"
    if auth_header:
        nuclei_cmd += f" -H {shlex.quote(f'Authorization: {auth_header}')}"
    nuclei, _ = run_command(nuclei_cmd, verbose, timeout=300)
    high = (nse + nuclei).lower().count("critical") + (nse + nuclei).lower().count("high")
    return {"raw": {"nmap_vuln": nse, "nuclei": nuclei}, "parsed": {"high_risk_count": high}}
