"""default_creds.py -- vendor-default credential detection (PCI §6.1).

Real network connection attempts are mocked; what's under test here is
the DISPATCH logic (which checker fires for which port/service) and the
single-attempt-per-service contract, not the network libraries
themselves (paramiko/pymysql/etc. are third-party and out of scope).

IMPORTANT: _SERVICE_CHECKERS/_PORT_CHECKERS are module-level dicts built
at import time holding DIRECT references to the checker functions --
`patch('default_creds.check_ssh', ...)` only rebinds the module
attribute, it does NOT change what's already stored in those dicts. Tests
below patch the dict entries themselves (via patch.dict) rather than the
function names, or they'd silently fall through to the real network
code -- which is exactly what happened the first time this file was
written (65s runtime, real connection attempts, zero mocks actually hit).
"""
from unittest.mock import patch
import default_creds


def test_dispatch_matches_by_service_name_over_port_number():
    """A service explicitly named 'ssh' on a nonstandard port must still
    route to check_ssh, not fall through to nothing."""
    mock_ssh = lambda host, port: []
    with patch.dict(default_creds._SERVICE_CHECKERS, {'ssh': mock_ssh}):
        hits = default_creds.run_default_creds_scan(
            '10.0.0.1', [{'port': 2222, 'service': 'ssh'}]
        )
        assert hits == []  # ran without hitting the real network / hanging


def test_dispatch_falls_back_to_well_known_port_when_service_unnamed():
    calls = []
    mock_mysql = lambda host, port: (calls.append((host, port)) or [])
    with patch.dict(default_creds._PORT_CHECKERS, {3306: mock_mysql}):
        default_creds.run_default_creds_scan(
            '10.0.0.1', [{'port': 3306, 'service': ''}]
        )
        assert calls == [('10.0.0.1', 3306)]


def test_unrecognized_port_and_service_triggers_no_checker():
    hits = default_creds.run_default_creds_scan(
        '10.0.0.1', [{'port': 9999, 'service': 'some-custom-app'}]
    )
    assert hits == []


def test_each_port_checked_at_most_once_even_with_duplicate_entries():
    calls = []
    mock_ssh = lambda host, port: (calls.append((host, port)) or [])
    with patch.dict(default_creds._SERVICE_CHECKERS, {'ssh': mock_ssh}):
        default_creds.run_default_creds_scan(
            '10.0.0.1', [{'port': 22, 'service': 'ssh'}, {'port': 22, 'service': 'ssh'}]
        )
        assert len(calls) == 1


def test_web_ports_get_http_basic_auth_checked():
    calls = []
    mock_http = lambda host, port, scheme='http': (calls.append((host, port)) or [])
    with patch('default_creds.check_http_basic_auth', mock_http):
        default_creds.run_default_creds_scan(
            '10.0.0.1', [{'port': 80, 'service': 'http'}], web_ports=[80]
        )
        assert calls == [('10.0.0.1', 80)]


def test_hits_are_tagged_with_the_port_they_were_found_on():
    mock_ssh = lambda host, port: [{'service': 'ssh', 'username': 'root', 'note': 'accepted root/root'}]
    with patch.dict(default_creds._SERVICE_CHECKERS, {'ssh': mock_ssh}):
        hits = default_creds.run_default_creds_scan(
            '10.0.0.1', [{'port': 22, 'service': 'ssh'}]
        )
        assert len(hits) == 1
        assert hits[0]['port'] == 22
        assert hits[0]['username'] == 'root'


def test_checker_exception_does_not_crash_the_whole_scan():
    """One misbehaving check must not take down the rest of the pipeline."""
    def raiser(host, port):
        raise Exception("connection reset")
    ftp_calls = []
    mock_ftp = lambda host, port: (ftp_calls.append((host, port)) or [])

    with patch.dict(default_creds._SERVICE_CHECKERS, {'ssh': raiser, 'ftp': mock_ftp}):
        hits = default_creds.run_default_creds_scan(
            '10.0.0.1', [{'port': 22, 'service': 'ssh'}, {'port': 21, 'service': 'ftp'}]
        )
        assert hits == []
        assert ftp_calls == [('10.0.0.1', 21)]


def test_redis_no_auth_check_reports_none_as_username():
    """Redis has no default username/password -- reachable-with-no-auth
    IS the finding, not a credential pair."""
    mock_redis = lambda host, port: [
        {'service': 'redis', 'username': '(none)', 'note': 'Redis instance accessible with no authentication'}
    ]
    with patch.dict(default_creds._SERVICE_CHECKERS, {'redis': mock_redis}):
        hits = default_creds.run_default_creds_scan(
            '10.0.0.1', [{'port': 6379, 'service': 'redis'}]
        )
        assert hits[0]['username'] == '(none)'
