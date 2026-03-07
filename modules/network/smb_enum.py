import shlex
from core.executor import run_command


def run(target, verbose=False):
    e4l, _ = run_command(f"enum4linux-ng -A {shlex.quote(target)}", verbose, timeout=240)
    smb, _ = run_command(f"smbclient -L //{shlex.quote(target)} -N", verbose)
    anon = "Anonymous login successful" in e4l or "Sharename" in smb
    smbv1 = "SMB1" in e4l or "SMBv1" in e4l
    return {"raw": {"enum4linux_ng": e4l, "smbclient": smb}, "parsed": {"anonymous_access": anon, "smbv1_enabled": smbv1, "high_risk_count": int(anon) + int(smbv1)}}
