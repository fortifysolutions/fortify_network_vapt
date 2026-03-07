import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"curl -s http://{shlex.quote(target)}:2375/version", verbose)
    exposed = "Version" in out or "ApiVersion" in out
    return {"raw": {"docker_api": out}, "parsed": {"docker_api_exposed": exposed, "high_risk_count": 1 if exposed else 0}}
