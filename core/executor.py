import shlex
import subprocess
from core.config import DEFAULT_TIMEOUT


def run_command(command, verbose=False, timeout=DEFAULT_TIMEOUT):
    try:
        cmd = ["stdbuf", "-oL"] + shlex.split(command)
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        out = (proc.stdout or "") + (proc.stderr or "")
        if verbose and out:
            print(out)
        return out, proc.returncode
    except subprocess.TimeoutExpired:
        return "[!] Command timed out.", 1
    except Exception as exc:
        return str(exc), 1
