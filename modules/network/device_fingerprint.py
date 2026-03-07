import re
import shlex

from core.executor import run_command
from core.oui_db import lookup_vendor


DEVICE_RULES = [
    (r"9100|jetdirect", "printer"),
    (r"rtsp|554|hikvision|dahua|axis", "cctv_camera"),
    (r"cisco|router|routing|ubiquiti|mikrotik", "router_or_access_point"),
    (r"switch|spanning-tree|lldp", "switch"),
    (r"fortinet|palo alto|checkpoint|firewall", "firewall"),
    (r"vmware|hyper-v|virtualbox|qemu|kvm", "virtual_machine_host")
]


VENDOR_DEVICE_HINTS = {
    "Axis": "cctv_camera",
    "Hikvision": "cctv_camera",
    "Dahua": "cctv_camera",
    "Hewlett Packard": "printer",
    "Brother": "printer",
    "Cisco": "router_or_access_point",
    "Juniper": "router_or_access_point",
    "Ubiquiti": "router_or_access_point",
    "MikroTik": "router_or_access_point",
    "Fortinet": "firewall",
    "VMware": "virtual_machine_host",
    "Microsoft Hyper-V": "virtual_machine_host",
    "VirtualBox": "virtual_machine_host",
    "QEMU/KVM": "virtual_machine_host",
}


def _extract_mac_vendor_from_scan(output: str):
    mac = ""
    vendor = ""
    for line in output.splitlines():
        line = line.strip()
        if line.lower().startswith("mac address:"):
            m = re.search(r"MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\((.*?)\))?", line)
            if m:
                mac = m.group(1).upper()
                vendor = (m.group(2) or "").strip()
                break
    if mac and not vendor:
        vendor = lookup_vendor(mac)
    return mac, vendor


def _infer_by_vendor(vendor_name: str):
    if not vendor_name:
        return None
    for key, label in VENDOR_DEVICE_HINTS.items():
        if key.lower() in vendor_name.lower():
            return label
    return None


def run(target, verbose=False):
    out, _ = run_command(f"nmap -sV -O -Pn {shlex.quote(target)}", verbose)
    low = out.lower()

    guessed = []
    for patt, label in DEVICE_RULES:
        if re.search(patt, low):
            guessed.append(label)

    mac, vendor = _extract_mac_vendor_from_scan(out)
    vendor_hint = _infer_by_vendor(vendor)
    if vendor_hint:
        guessed.append(vendor_hint)

    guessed = list(dict.fromkeys(guessed))
    if not guessed:
        guessed = ["server_or_workstation"]

    edge_device_types = {"printer", "cctv_camera", "switch", "router_or_access_point", "firewall"}
    medium_risk = 1 if any(x in edge_device_types for x in guessed) else 0

    return {
        "raw": {"fingerprint": out},
        "parsed": {
            "device_types": guessed,
            "mac_address": mac or None,
            "vendor": vendor or "Unknown",
            "vendor_confidence": "medium" if vendor and vendor != "Unknown" else "low",
            "medium_risk_count": medium_risk,
        }
    }
