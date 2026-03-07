# Minimal high-value OUI/vendor mapping for infrastructure fingerprinting.
# Keys are first 3 bytes in uppercase colon format (AA:BB:CC).
OUI_VENDOR_MAP = {
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "3C:5A:B4": "Google",
    "F4:F5:D8": "Google",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:05:69": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:25:90": "Super Micro",
    "00:1A:A0": "Dell",
    "00:1B:21": "Intel",
    "00:1E:C9": "Cisco",
    "00:1F:9D": "Cisco",
    "00:09:0F": "Fortinet",
    "00:0C:43": "Ruckus",
    "00:17:9A": "D-Link",
    "00:14:22": "Dell",
    "00:11:32": "Synology",
    "00:26:76": "KYE/Printer",
    "00:04:A3": "Hewlett Packard",
    "00:80:77": "Brother",
    "00:1F:F3": "Nikon/CCTV",
    "00:40:8C": "Axis",
    "AC:64:62": "Hikvision",
    "BC:AD:28": "Dahua",
    "FC:AA:14": "Ubiquiti",
    "44:D9:E7": "MikroTik",
    "C8:D7:19": "TP-Link",
    "00:17:88": "Nortel/Avaya",
    "00:21:9B": "Netgear",
    "00:24:D7": "Huawei",
    "4C:5E:0C": "Juniper",
    "00:16:3E": "Xen",
}


def lookup_vendor(mac_address: str) -> str:
    if not mac_address:
        return "Unknown"
    parts = mac_address.upper().replace("-", ":").split(":")
    if len(parts) < 3:
        return "Unknown"
    oui = ":".join(parts[:3])
    return OUI_VENDOR_MAP.get(oui, "Unknown")
