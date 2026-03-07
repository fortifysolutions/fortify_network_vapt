#!/usr/bin/env python3

import argparse
import importlib
import os

from core.config import APP_NAME, VERSION, OUTPUT_DIR
from core.precheck import run_precheck
from core.profile_loader import load_profile
from core.reporter import initialize_report, save_reports

HOST_BATCH_MODULES = {
    "network.port_scan",
    "network.service_detection",
    "network.banner_grab",
    "network.os_detection",
    "network.device_fingerprint",
    "network.snmp_enumeration",
    "network.smb_enum",
    "network.ssh_audit",
    "network.tls_scan",
    "vuln.vuln_scan",
    "exposure.ldap_enumeration",
    "exposure.ntp_amplification_check",
    "exposure.ipmi_detection",
    "exposure.docker_api_exposure",
    "exposure.kubernetes_api_exposure",
    "exposure.redis_exposure",
    "exposure.mongodb_exposure",
    "exposure.insecure_protocol_detection",
}


def dedupe(items):
    return list(dict.fromkeys([x for x in items if x]))


def run_module(mod, target, verbose=False):
    module = importlib.import_module(f"modules.{mod}")
    return module.run(target, verbose)


def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--target", required=True, help="Domain, IP, or CIDR")
    parser.add_argument("--profile", default="deep", help="quick/standard/deep")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--auto-install", action="store_true")
    parser.add_argument("--max-hosts", type=int, default=32)
    args = parser.parse_args()

    print(f"\n{APP_NAME} v{VERSION}\n")
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    if not run_precheck(auto_install=args.auto_install):
        raise SystemExit(1)

    modules = load_profile(args.profile)
    if not modules:
        raise SystemExit(1)

    report = initialize_report(args.target, args.profile)
    context_hosts = [args.target]

    for mod in modules:
        try:
            if mod == "network.host_discovery":
                result = run_module(mod, args.target, args.verbose)
                discovered = result.get("parsed", {}).get("live_hosts", [])
                context_hosts = dedupe(discovered or context_hosts)[: max(1, args.max_hosts)]
            elif mod in HOST_BATCH_MODULES:
                batch = {}
                for h in context_hosts:
                    batch[h] = run_module(mod, h, args.verbose)
                result = {"raw": {"batch": batch}, "parsed": {"host_count": len(context_hosts)}}
            else:
                result = run_module(mod, args.target, args.verbose)

            report["modules"][mod] = result
            print(f"[+] Completed: {mod}")
        except Exception as exc:
            report["modules"][mod] = {"error": str(exc)}
            print(f"[!] Failed: {mod} -> {exc}")

    report["summary"]["assessed_hosts"] = context_hosts
    save_reports(report)


if __name__ == "__main__":
    main()
