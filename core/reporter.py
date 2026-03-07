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
        "summary": {}
    }


def _module_result_iter(module_data):
    if not isinstance(module_data, dict):
        return
    if "raw" in module_data and isinstance(module_data.get("raw"), dict) and "batch" in module_data["raw"]:
        for host, result in module_data["raw"]["batch"].items():
            yield host, result
    else:
        yield "target", module_data


def compute_risk(report):
    high = 0
    medium = 0
    for _, module_data in report.get("modules", {}).items():
        for _, result in _module_result_iter(module_data):
            parsed = result.get("parsed", {}) if isinstance(result, dict) else {}
            high += int(parsed.get("high_risk_count", 0))
            medium += int(parsed.get("medium_risk_count", 0))
    score = min(100, high * 10 + medium * 4)
    sev = "Low" if score < 35 else ("Medium" if score < 70 else "High")
    return score, sev


def build_executive_rows(report):
    rows = []
    for module_name, module_data in report.get("modules", {}).items():
        for host, result in _module_result_iter(module_data):
            status = "ok"
            high = 0
            medium = 0
            finding_summary = ""
            if isinstance(result, dict):
                if "error" in result:
                    status = "error"
                    finding_summary = str(result.get("error", ""))[:200]
                parsed = result.get("parsed", {})
                if isinstance(parsed, dict):
                    high = int(parsed.get("high_risk_count", 0))
                    medium = int(parsed.get("medium_risk_count", 0))
                    keys = [k for k in parsed.keys() if any(x in k for x in ["exposed", "risk", "anonymous", "weak", "vulnerable", "allowed", "device_types", "vendor"])]
                    snippets = []
                    for key in keys[:6]:
                        val = parsed.get(key)
                        snippets.append(f"{key}={val}")
                    finding_summary = "; ".join(snippets)[:300]
            rows.append({
                "module": module_name,
                "host": host,
                "status": status,
                "high_risk_count": high,
                "medium_risk_count": medium,
                "finding_summary": finding_summary,
            })
    return rows


def _safe_report_stem(report):
    raw_target = report.get("target", "unknown_target")
    safe_target = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in str(raw_target))
    raw_time = report.get("timestamp", datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    safe_time = raw_time.replace(":", "-").replace(" ", "_")
    return f"{safe_target}_{safe_time}"


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

    body = [
        "<html><head><meta charset='utf-8'><title>Network VAPT Report</title></head><body>",
        f"<h1>Fortify Network VAPT</h1><p><b>Target:</b> {html.escape(report['target'])}</p>",
        f"<p><b>Profile:</b> {html.escape(report['profile'])}</p>",
        f"<p><b>Risk Score:</b> {score}/100 ({sev})</p>",
        f"<p><b>Executive CSV:</b> {html.escape(csv_path)}</p>",
    ]
    for mod, data in report.get("modules", {}).items():
        body.append(f"<h2>{html.escape(mod)}</h2><pre>{html.escape(json.dumps(data, indent=2)[:8000])}</pre>")
    body.append("</body></html>")

    with open(html_path, "w", encoding="utf-8") as f:
        f.write("\n".join(body))

    print(f"[+] Reports saved: {json_path}, {html_path}, {csv_path}")
