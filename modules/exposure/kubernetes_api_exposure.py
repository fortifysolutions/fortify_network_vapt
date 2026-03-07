import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"curl -sk https://{shlex.quote(target)}:6443/version", verbose)
    exposed = "major" in out.lower() and "minor" in out.lower()
    return {"raw": {"k8s_api": out}, "parsed": {"kubernetes_api_exposed": exposed, "high_risk_count": 1 if exposed else 0}}
