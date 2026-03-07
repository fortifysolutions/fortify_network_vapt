APP_NAME = "Fortify Network VAPT"
VERSION = "1.0.0"
OUTPUT_DIR = "output"
DEFAULT_TIMEOUT = 180

REQUIRED_TOOLS = [
    "whois", "dig", "host", "nmap", "fping", "arp-scan", "masscan",
    "snmpwalk", "onesixtyone", "smbclient", "enum4linux-ng", "sslscan",
    "testssl.sh", "nuclei", "curl", "ldapsearch", "ipmitool", "redis-cli",
    "mongosh", "traceroute", "kubectl", "docker", "stdbuf"
]

WELL_KNOWN_PORTS = {
    22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
    80: "http", 110: "pop3", 123: "ntp", 135: "rpc", 137: "netbios",
    138: "netbios", 139: "smb", 161: "snmp", 389: "ldap", 443: "https",
    445: "smb", 465: "smtps", 514: "syslog", 587: "smtp", 636: "ldaps",
    873: "rsync", 902: "vmware", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2375: "docker_api", 3306: "mysql", 3389: "rdp", 5432: "postgres",
    5601: "kibana", 5900: "vnc", 6379: "redis", 6443: "k8s_api", 8080: "http_alt",
    8443: "https_alt", 9000: "admin", 9100: "printer_jetdirect", 27017: "mongodb",
    4786: "smart_install", 5000: "cctv_common", 554: "rtsp", 1723: "pptp", 623: "ipmi"
}
