import re
import shlex
from core.executor import run_command

VULN_MARKERS = ["vulnerable", "vulnerability", "cve-"]
SEVERITY_MAP = {"critical": 3, "high": 2, "medium": 1}


def _parse_nmap_vuln(output: str):
    findings = []
    current_port = None
    for line in output.splitlines():
        if line.startswith("PORT "):
            current_port = None
            continue
        m = re.match(r"^(\d+)/(tcp|udp)\s+open", line)
        if m:
            current_port = m.group(1)
            continue
        if current_port and line.strip().startswith("|"):
            text = line.strip("| ")
            low = text.lower()
            if any(marker in low for marker in VULN_MARKERS):
                findings.append({
                    "source": "nmap",
                    "port": current_port,
                    "summary": text[:240],
                    "severity": "high" if "cve" in low or "critical" in low else "medium",
                })
    return findings


def _parse_nuclei(output: str):
    findings = []
    for line in output.splitlines():
        low = line.lower()
        sev = "medium"
        if "[critical]" in low:
            sev = "critical"
        elif "[high]" in low:
            sev = "high"
        findings.append({
            "source": "nuclei",
            "port": None,
            "summary": line[:240],
            "severity": sev,
        })
    return findings


def run(target, verbose=False, config=None):
    cfg = config or {}
    cookie = (cfg.get("cookie") or "").strip()
    auth_header = (cfg.get("auth_header") or "").strip()

    nmap_out, _ = run_command(f"nmap --script vuln -Pn {shlex.quote(target)}", verbose, timeout=300)
    nuclei_cmd = f"nuclei -target {shlex.quote(target)} -ni -silent"
    if cookie:
        nuclei_cmd += f" -H {shlex.quote(f'Cookie: {cookie}') }"
    if auth_header:
        nuclei_cmd += f" -H {shlex.quote(f'Authorization: {auth_header}') }"
    nuclei_out, _ = run_command(nuclei_cmd, verbose, timeout=300)

    findings = _parse_nmap_vuln(nmap_out) + _parse_nuclei(nuclei_out)
    high = sum(1 for f in findings if f["severity"] in {"high", "critical"})
    medium = sum(1 for f in findings if f["severity"] == "medium")

    return {
        "status": "ok",
        "raw": {"nmap_vuln": nmap_out, "nuclei": nuclei_out},
        "parsed": {
            "findings": findings,
            "high_risk_count": high,
            "medium_risk_count": medium,
        },
    }
