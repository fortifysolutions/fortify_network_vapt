import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"redis-cli -h {shlex.quote(target)} -p 6379 ping", verbose)
    exposed = "PONG" in out
    return {"raw": {"redis": out}, "parsed": {"redis_unauthenticated": exposed, "high_risk_count": 1 if exposed else 0}}
