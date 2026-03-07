#!/usr/bin/env python3

import argparse
import importlib
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

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


def run_batch_module(mod, hosts, verbose=False, max_workers=8):
    batch = {}
    errors = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_map = {executor.submit(run_module, mod, host, verbose): host for host in hosts}
        for future in as_completed(future_map):
            host = future_map[future]
            try:
                result = future.result()
            except Exception as exc:
                result = {"error": str(exc)}
            batch[host] = result
            if isinstance(result, dict) and "error" in result:
                errors += 1

    return {
        "raw": {"batch": batch},
        "parsed": {
            "host_count": len(hosts),
            "errors": errors,
            "successful": len(hosts) - errors,
        }
    }


def main():
    parser = argparse.ArgumentParser(description=APP_NAME)
    parser.add_argument("--target", required=True, help="Domain, IP, or CIDR")
    parser.add_argument("--profile", default="deep", help="quick/standard/deep")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--auto-install", action="store_true")
    parser.add_argument("--max-hosts", type=int, default=32)
    parser.add_argument("--max-workers", type=int, default=8, help="Parallel workers for host-level module execution")
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
                result = run_batch_module(
                    mod,
                    context_hosts,
                    verbose=args.verbose,
                    max_workers=max(1, args.max_workers),
                )
            else:
                result = run_module(mod, args.target, args.verbose)

            report["modules"][mod] = result
            print(f"[+] Completed: {mod}")
        except Exception as exc:
            report["modules"][mod] = {"error": str(exc)}
            print(f"[!] Failed: {mod} -> {exc}")

    report["summary"]["assessed_hosts"] = context_hosts
    report["summary"]["max_workers"] = max(1, args.max_workers)
    save_reports(report)


if __name__ == "__main__":
    main()
