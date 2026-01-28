from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import timedelta, datetime
from .parsers import AuthEvent

@dataclass
class BruteForceAlert:
    ip: str
    window_start: datetime
    window_end: datetime
    count_in_window: int
    threshold: int

def detect_bruteforce(
    events: list[AuthEvent],
    *,
    threshold: int = 10,
    window_minutes: int = 10,
    event_types: tuple[str, ...] = ("failed_password",),
) -> list[BruteForceAlert]:
    """Detect brute-force behavior by IP with a sliding time window."""
    window = timedelta(minutes=window_minutes)
    by_ip: dict[str, list[datetime]] = defaultdict(list)

    for ev in events:
        if ev.event_type in event_types:
            by_ip[ev.ip].append(ev.ts)

    alerts: list[BruteForceAlert] = []
    for ip, times in by_ip.items():
        times.sort()
        dq: deque[datetime] = deque()
        last_alert_end: datetime | None = None

        for t in times:
            dq.append(t)
            while dq and (t - dq[0]) > window:
                dq.popleft()

            if len(dq) >= threshold:
                start = dq[0]
                end = t
                # avoid spamming: if we're still inside last alerted window, skip
                if last_alert_end is None or start > last_alert_end:
                    alerts.append(BruteForceAlert(
                        ip=ip,
                        window_start=start,
                        window_end=end,
                        count_in_window=len(dq),
                        threshold=threshold
                    ))
                    last_alert_end = end
    # sort by severity then time
    alerts.sort(key=lambda a: (-(a.count_in_window), a.window_start))
    return alerts

def summarize(events: list[AuthEvent]) -> dict:
    total = len(events)
    failed = sum(1 for e in events if e.event_type == "failed_password")
    invalid = sum(1 for e in events if e.event_type == "invalid_user")
    unique_ips = len({e.ip for e in events})
    first = events[0].ts.isoformat() if events else None
    last = events[-1].ts.isoformat() if events else None
    return {
        "total_events": total,
        "failed_password": failed,
        "invalid_user": invalid,
        "unique_source_ips": unique_ips,
        "time_range": {"start": first, "end": last},
    }
