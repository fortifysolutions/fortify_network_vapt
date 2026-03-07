import shlex
from core.executor import run_command


def run(target, verbose=False):
    probe, _ = run_command(f"onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt {shlex.quote(target)}", verbose)
    walk, _ = run_command(f"snmpwalk -v2c -c public {shlex.quote(target)} 1.3.6.1.2.1.1", verbose)
    weak = "Timeout" not in walk and "No Such Object" not in walk and walk.strip() != ""
    return {"raw": {"onesixtyone": probe, "snmpwalk": walk}, "parsed": {"snmp_public_access": weak, "high_risk_count": 1 if weak else 0}}
