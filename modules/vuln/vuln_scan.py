import shlex
from core.executor import run_command


def run(target, verbose=False):
    nse, _ = run_command(f"nmap --script vuln -Pn {shlex.quote(target)}", verbose, timeout=300)
    nuclei, _ = run_command(f"nuclei -target {shlex.quote(target)} -ni -silent", verbose, timeout=300)
    high = (nse + nuclei).lower().count("critical") + (nse + nuclei).lower().count("high")
    return {"raw": {"nmap_vuln": nse, "nuclei": nuclei}, "parsed": {"high_risk_count": high}}
