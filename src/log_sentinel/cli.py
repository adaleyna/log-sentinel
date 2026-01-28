from __future__ import annotations

import argparse
from .parsers import parse_auth_log
from .detectors import detect_bruteforce
from .report import build_report, write_report

def main() -> int:
    ap = argparse.ArgumentParser(description="Parse SSH auth logs and detect brute-force patterns (authorized use only).")
    ap.add_argument("--log", required=True, help="Path to auth.log (or similar)")
    ap.add_argument("--threshold", type=int, default=10, help="Failures in window to trigger alert")
    ap.add_argument("--window-minutes", type=int, default=10, help="Sliding window size in minutes")
    ap.add_argument("--out", default="output", help="Output directory for reports")
    args = ap.parse_args()

    events = parse_auth_log(args.log)
    alerts = detect_bruteforce(events, threshold=args.threshold, window_minutes=args.window_minutes)
    report = build_report(events, alerts)
    write_report(args.out, report)

    print(f"Parsed events: {len(events)} | Alerts: {len(alerts)} | Output: {args.out}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
