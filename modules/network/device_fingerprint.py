import re
import shlex
from core.executor import run_command


DEVICE_RULES = [
    (r"9100|jetdirect", "printer"),
    (r"rtsp|554|hikvision|dahua|axis", "cctv_camera"),
    (r"cisco|router|routing", "router"),
    (r"switch|spanning-tree", "switch"),
    (r"fortinet|palo alto|checkpoint|firewall", "firewall"),
    (r"vmware|hyper-v|virtualbox|qemu", "virtual_machine_host")
]


def run(target, verbose=False):
    out, _ = run_command(f"nmap -sV -O -Pn {shlex.quote(target)}", verbose)
    low = out.lower()
    guessed = []
    for patt, label in DEVICE_RULES:
        if re.search(patt, low):
            guessed.append(label)
    guessed = list(dict.fromkeys(guessed))
    if not guessed:
        guessed = ["server_or_workstation"]
    return {"raw": {"fingerprint": out}, "parsed": {"device_types": guessed, "medium_risk_count": 1 if "printer" in guessed or "cctv_camera" in guessed else 0}}
