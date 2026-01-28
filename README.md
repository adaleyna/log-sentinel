# Log Sentinel (SSH auth.log brute-force detector)

**Purpose:** Parse Linux `auth.log` (sshd) and detect brute-force patterns, then produce a clean report.

> Use **only on systems you own or have explicit authorization to analyze.**

## Features
- Parses common `sshd` failure patterns from `auth.log`
- Detects "N failures within M minutes" brute-force behavior
- Exports `report.json` and `report.md`
- Includes unit tests + GitHub Actions CI

## Quickstart
```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
pip install pytest
```

Run:
```bash
PYTHONPATH=src python -m log_sentinel.cli --log data/sample_auth.log --threshold 10 --window-minutes 10 --out output
```

Run tests:
```bash
PYTHONPATH=src pytest
```

Run on the included sample:
```bash
log-sentinel --log data/sample_auth.log --threshold 10 --window-minutes 10 --out output
```

Outputs:
- `output/report.json`
- `output/report.md`

## Example output (excerpt)
- Total failed attempts: 45
- Unique source IPs: 6
- Alerts: 2 (threshold exceeded)

## Notes
- Timestamp year is assumed as the current year (typical for syslog-style lines).
- The parser is defensive and will skip lines it can't interpret.

## Examples
See `examples/` for sample report outputs.
