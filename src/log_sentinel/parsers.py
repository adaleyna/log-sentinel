from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from dateutil import tz

# Typical sshd failure examples:
# Jan 28 12:34:56 host sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2
# Jan 28 12:34:57 host sshd[123]: Failed password for root from 5.6.7.8 port 2222 ssh2
# Jan 28 12:35:01 host sshd[123]: Invalid user test from 9.9.9.9 port 1234

FAILED_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Failed password\s+for\s+(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

INVALID_USER_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd\[\d+\]:\s+Invalid user\s+(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

@dataclass(frozen=True)
class AuthEvent:
    ts: datetime
    event_type: str  # "failed_password" | "invalid_user"
    ip: str
    user: str | None
    raw: str

MONTHS = {m: i for i, m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

def _parse_syslog_ts(mon: str, day: str, time_s: str) -> datetime:
    # Syslog lines omit year/timezone. Assume current year and local timezone.
    year = datetime.now().year
    month = MONTHS.get(mon, 1)
    hh, mm, ss = (int(x) for x in time_s.split(":"))
    dt = datetime(year, month, int(day), hh, mm, ss)
    # naive datetime is fine; keep consistent
    return dt

def parse_auth_log_line(line: str) -> AuthEvent | None:
    line = line.rstrip("\n")
    m = FAILED_RE.match(line)
    if m:
        ts = _parse_syslog_ts(m.group("mon"), m.group("day"), m.group("time"))
        return AuthEvent(ts=ts, event_type="failed_password", ip=m.group("ip"), user=m.group("user"), raw=line)

    m = INVALID_USER_RE.match(line)
    if m:
        ts = _parse_syslog_ts(m.group("mon"), m.group("day"), m.group("time"))
        return AuthEvent(ts=ts, event_type="invalid_user", ip=m.group("ip"), user=m.group("user"), raw=line)

    return None

def parse_auth_log(path: str) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            ev = parse_auth_log_line(line)
            if ev:
                events.append(ev)
    events.sort(key=lambda e: e.ts)
    return events
