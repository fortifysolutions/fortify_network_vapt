import datetime
import html
import json
import os
from core.config import OUTPUT_DIR


def initialize_report(target, profile):
    return {
        "target": target,
        "profile": profile,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "modules": {},
        "summary": {}
    }


def compute_risk(report):
    high = 0
    medium = 0
    for _, data in report.get("modules", {}).items():
        parsed = data.get("parsed", {}) if isinstance(data, dict) else {}
        high += int(parsed.get("high_risk_count", 0))
        medium += int(parsed.get("medium_risk_count", 0))
    score = min(100, high * 10 + medium * 4)
    sev = "Low" if score < 35 else ("Medium" if score < 70 else "High")
    return score, sev


def save_reports(report):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    score, sev = compute_risk(report)
    report["summary"]["risk_score"] = score
    report["summary"]["severity"] = sev

    with open(os.path.join(OUTPUT_DIR, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    body = [
        "<html><head><meta charset='utf-8'><title>Network VAPT Report</title></head><body>",
        f"<h1>Fortify Network VAPT</h1><p><b>Target:</b> {html.escape(report['target'])}</p>",
        f"<p><b>Profile:</b> {html.escape(report['profile'])}</p>",
        f"<p><b>Risk Score:</b> {score}/100 ({sev})</p>",
    ]
    for mod, data in report.get("modules", {}).items():
        body.append(f"<h2>{html.escape(mod)}</h2><pre>{html.escape(json.dumps(data, indent=2)[:8000])}</pre>")
    body.append("</body></html>")

    with open(os.path.join(OUTPUT_DIR, "report.html"), "w", encoding="utf-8") as f:
        f.write("\n".join(body))

    print("[+] Reports saved: output/report.json, output/report.html")
