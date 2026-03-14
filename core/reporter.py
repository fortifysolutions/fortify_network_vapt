import csv
import datetime
import html
import json
import os
from core.config import OUTPUT_DIR


def initialize_report(target, profile):
    return {
        "target": target,
        "profile": profile,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "modules": {},
        "summary": {},
    }


def _safe_report_stem(report):
    raw_target = report.get("target", "unknown_target")
    safe_target = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(raw_target))
    raw_time = report.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    safe_time = raw_time.replace(":", "-").replace(" ", "_")
    return f"{safe_target}_{safe_time}"


def _collect_hosts(modules):
    data = modules.get("network.host_discovery", {})
    parsed = data.get("parsed", {}) if isinstance(data, dict) else {}
    return parsed.get("live_hosts", []), parsed.get("unreachable_hosts", [])


def _collect_ports(modules):
    data = modules.get("network.port_scan", {})
    parsed = data.get("parsed", {}) if isinstance(data, dict) else {}
    return parsed.get("ports", [])


def _collect_findings(modules):
    data = modules.get("vuln.vuln_scan", {})
    parsed = data.get("parsed", {}) if isinstance(data, dict) else {}
    return parsed.get("findings", []), parsed.get("high_risk_count", 0), parsed.get("medium_risk_count", 0)


def compute_risk(report):
    findings, high, medium = _collect_findings(report.get("modules", {}))
    high += report.get("modules", {}).get("network.port_scan", {}).get("parsed", {}).get("high_risk_count", 0) if isinstance(report.get("modules", {}).get("network.port_scan", {}), dict) else 0
    medium += report.get("modules", {}).get("network.port_scan", {}).get("parsed", {}).get("medium_risk_count", 0) if isinstance(report.get("modules", {}).get("network.port_scan", {}), dict) else 0
    score = min(100, high * 10 + medium * 4)
    sev = "Low" if score < 35 else ("Medium" if score < 70 else "High")
    return score, sev


def build_executive_rows(report):
    rows = []
    modules = report.get("modules", {})
    hosts, _ = _collect_hosts(modules)
    ports = _collect_ports(modules)
    findings, _, _ = _collect_findings(modules)

    for h in hosts:
        rows.append({"module": "host_discovery", "host": h, "status": "ok", "high_risk_count": 0, "medium_risk_count": 0, "finding_summary": "live"})

    for p in ports:
        rows.append({
            "module": "port_scan",
            "host": report.get("target", "target"),
            "status": p.get("state", "ok"),
            "high_risk_count": 1 if p.get("risk") == "high" else 0,
            "medium_risk_count": 1 if p.get("risk") == "medium" else 0,
            "finding_summary": f"{p.get('port')}/{p.get('proto')} {p.get('service_hint')} {p.get('version', '')} risk={p.get('risk')}",
        })

    for f in findings:
        rows.append({
            "module": "vuln_scan",
            "host": report.get("target", "target"),
            "status": "finding",
            "high_risk_count": 1 if f.get("severity") in {"high", "critical"} else 0,
            "medium_risk_count": 1 if f.get("severity") == "medium" else 0,
            "finding_summary": f"{f.get('source')} {f.get('port') or ''} {f.get('severity')}: {f.get('summary')}",
        })
    return rows


def save_csv_executive_summary(report, filename=None):
    rows = build_executive_rows(report)
    if not filename:
        filename = f"{_safe_report_stem(report)}_executive_summary.csv"
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["module", "host", "status", "high_risk_count", "medium_risk_count", "finding_summary"],
        )
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return path


def _render_table(headers, rows):
    head_html = "".join([f"<th>{html.escape(h)}</th>" for h in headers])
    body_html = "".join([
        "<tr>" + "".join([f"<td>{html.escape(str(row.get(col, '')))}</td>" for col in headers]) + "</tr>"
        for row in rows
    ])
    return f"<table border='1' cellspacing='0' cellpadding='6'><thead><tr>{head_html}</tr></thead><tbody>{body_html}</tbody></table>"


def save_reports(report):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    score, sev = compute_risk(report)
    report["summary"]["risk_score"] = score
    report["summary"]["severity"] = sev

    stem = _safe_report_stem(report)
    json_path = os.path.join(OUTPUT_DIR, f"{stem}.json")
    html_path = os.path.join(OUTPUT_DIR, f"{stem}.html")
    csv_path = save_csv_executive_summary(report)

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    modules = report.get("modules", {})
    live_hosts, unreachable = _collect_hosts(modules)
    ports = _collect_ports(modules)
    findings, high, medium = _collect_findings(modules)

    host_table = _render_table(["Host", "Status"], [{"Host": h, "Status": "live"} for h in live_hosts] + [{"Host": h, "Status": "unreachable"} for h in unreachable])
    port_table = _render_table(["Port", "Proto", "State", "Service", "Version", "Risk"], [
        {
            "Port": p.get("port"),
            "Proto": p.get("proto"),
            "State": p.get("state"),
            "Service": p.get("service_hint"),
            "Version": p.get("version"),
            "Risk": p.get("risk"),
        }
        for p in ports
    ])
    vuln_table = _render_table(["Source", "Port", "Severity", "Summary"], [
        {
            "Source": f.get("source"),
            "Port": f.get("port") or "-",
            "Severity": f.get("severity"),
            "Summary": f.get("summary"),
        }
        for f in findings
    ])

    body = [
        "<html><head><meta charset='utf-8'><title>Network VAPT Report</title></head><body>",
        f"<h1>Fortify Network VAPT</h1><p><b>Target:</b> {html.escape(report['target'])}</p>",
        f"<p><b>Profile:</b> {html.escape(report['profile'])}</p>",
        f"<p><b>Risk Score:</b> {score}/100 ({sev})</p>",
        f"<p><b>Executive CSV:</b> {html.escape(csv_path)}</p>",
        "<h2>Hosts</h2>", host_table,
        "<h2>Ports</h2>", port_table,
        "<h2>Vulnerabilities</h2>", vuln_table,
    ]

    for mod, data in modules.items():
        body.append(f"<h3>{html.escape(mod)}</h3><pre>{html.escape(json.dumps(data, indent=2)[:8000])}</pre>")

    body.append("</body></html>")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(body))

    print(f"[+] Reports saved: {json_path}, {html_path}, {csv_path}")
