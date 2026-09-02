"""eol_os.py -- unsupported-OS auto-fail matching (PCI §7)."""
from datetime import date
import eol_os


def test_eol_match_is_flagged_when_past_eol_date():
    result = eol_os.check_eol("Microsoft Windows Server 2008 R2", as_of=date(2026, 8, 16))
    assert result is not None
    assert result['is_eol'] is True
    assert result['matched_name'] == 'Windows Server 2008 R2'


def test_matched_but_not_yet_eol_is_not_flagged():
    result = eol_os.check_eol("Ubuntu 18.04", as_of=date(2021, 1, 1))
    assert result is not None
    assert result['is_eol'] is False


def test_unknown_os_string_returns_none_not_a_false_safe_signal():
    """Unmatched must mean 'unknown,' never silently treated as safe."""
    assert eol_os.check_eol("Some Custom Embedded OS 3.2") is None


def test_empty_fingerprint_returns_none():
    assert eol_os.check_eol("") is None
    assert eol_os.check_eol(None) is None


def test_specific_match_beats_generic_windows_server_shadowing():
    """Windows Server 2008 R2 must not get shadowed by a bare '2008' entry."""
    result = eol_os.check_eol("Microsoft Windows Server 2008 R2 Standard", as_of=date(2026, 1, 1))
    assert result['matched_name'] == 'Windows Server 2008 R2'
