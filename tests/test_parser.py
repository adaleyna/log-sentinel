from log_sentinel.parsers import parse_auth_log_line

def test_parse_failed_password():
    line = "Jan 28 12:34:56 host sshd[123]: Failed password for invalid user admin from 1.2.3.4 port 12345 ssh2"
    ev = parse_auth_log_line(line)
    assert ev is not None
    assert ev.event_type == "failed_password"
    assert ev.ip == "1.2.3.4"
    assert ev.user == "admin"

def test_parse_invalid_user():
    line = "Jan 28 12:35:01 host sshd[123]: Invalid user test from 9.9.9.9 port 1234"
    ev = parse_auth_log_line(line)
    assert ev is not None
    assert ev.event_type == "invalid_user"
    assert ev.ip == "9.9.9.9"
    assert ev.user == "test"
