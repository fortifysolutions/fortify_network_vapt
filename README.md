# Fortify Network VAPT

Network-only VAPT framework for internal infrastructure assessments.

## Workflow
WHOIS + DNS -> Host Discovery -> Fast Port Scan -> Service Detection -> Banner Grab -> OS Detection -> SNMP -> SMB -> SSH -> TLS -> Vulnerability Scan -> Risk Scoring

## Device Coverage
- Servers / VMs
- Printers
- CCTV cameras
- Switches
- Routers / Access Points
- Firewalls

## Modules Included
- Recon: WHOIS, DNS enum, DNS zone transfer, traceroute mapping
- Discovery/Enumeration: host discovery, port scan, service detection, banner grab, OS detection, device fingerprint
- Infrastructure checks: SNMP, SMB, SSH, TLS
- Exposure checks: LDAP enum, NTP amplification, IPMI exposure, Docker API, Kubernetes API, Redis, MongoDB, insecure protocols
- Vulnerability detection: Nmap vuln scripts + Nuclei
- Risk scoring/reporting: JSON + HTML

## Profiles
- `quick`
- `standard`
- `deep`

## Usage
```bash
python3 main.py --target 10.10.10.0/24 --profile deep
python3 main.py --target example.internal --profile standard
```

## Notes
- Strict precheck is enforced. Missing required tools causes immediate exit.
- Authorized internal testing only.
