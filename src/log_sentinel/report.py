from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from .parsers import AuthEvent
from .detectors import BruteForceAlert, summarize

def build_report(events: list[AuthEvent], alerts: list[BruteForceAlert]) -> dict:
    ip_counts = Counter([e.ip for e in events if e.event_type in ("failed_password","invalid_user")])
    top_ips = [{"ip": ip, "count": cnt} for ip, cnt in ip_counts.most_common(10)]

    return {
        "summary": summarize(events),
        "top_source_ips": top_ips,
        "alerts": [
            {
                "ip": a.ip,
                "window_start": a.window_start.isoformat(),
                "window_end": a.window_end.isoformat(),
                "count_in_window": a.count_in_window,
                "threshold": a.threshold,
            } for a in alerts
        ],
    }

def write_report(out_dir: str, report: dict) -> tuple[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / "report.json"
    md_path = out / "report.md"

    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")

    s = report.get("summary", {})
    lines = []
    lines.append("# Log Sentinel Report")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- Total events: {s.get('total_events')}")
    lines.append(f"- Failed password: {s.get('failed_password')}")
    lines.append(f"- Invalid user: {s.get('invalid_user')}")
    lines.append(f"- Unique source IPs: {s.get('unique_source_ips')}")
    tr = s.get("time_range", {})
    lines.append(f"- Time range: {tr.get('start')} -> {tr.get('end')}")
    lines.append("")
    lines.append("## Top source IPs")
    for row in report.get("top_source_ips", []):
        lines.append(f"- {row['ip']}: {row['count']}")
    lines.append("")
    lines.append("## Alerts")
    if report.get("alerts"):
        for a in report["alerts"]:
            lines.append(f"- **{a['ip']}**: {a['count_in_window']} failures between {a['window_start']} and {a['window_end']} (threshold {a['threshold']})")
    else:
        lines.append("- No alerts triggered.")
    lines.append("")

    md_path.write_text("\n".join(lines), encoding="utf-8")
    return str(json_path), str(md_path)
