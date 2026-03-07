import shlex
from core.executor import run_command


def run(target, verbose=False):
    out, _ = run_command(f"mongosh --host {shlex.quote(target)} --port 27017 --eval 'db.runCommand({{ ping: 1 }})'", verbose)
    exposed = '"ok" : 1' in out or '"ok": 1' in out
    return {"raw": {"mongodb": out}, "parsed": {"mongodb_unauthenticated": exposed, "high_risk_count": 1 if exposed else 0}}
