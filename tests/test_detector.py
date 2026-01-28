from log_sentinel.parsers import parse_auth_log
from log_sentinel.detectors import detect_bruteforce

def test_detect_bruteforce_sample():
    events = parse_auth_log("data/sample_auth.log")
    alerts = detect_bruteforce(events, threshold=10, window_minutes=10)
    assert len(alerts) >= 1
    assert any(a.ip == "91.121.55.2" for a in alerts)
