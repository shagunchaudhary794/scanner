"""cvss_engine.py -- NVD-backed CVSS scoring, fallback chain, and the
Postgres cache. resolve_cvss needs a real db/CveCache table, so these use
the `app`/`db` fixtures rather than being pure-logic."""
from unittest.mock import patch
import cvss_engine


def test_cvss_version_preference_v31_beats_v20():
    metrics = {
        'cvssMetricV31': [{'type': 'Primary', 'cvssData': {'baseScore': 9.8}}],
        'cvssMetricV2': [{'type': 'Primary', 'cvssData': {'baseScore': 7.5}}],
    }
    score, source = cvss_engine._extract_best_cvss(metrics)
    assert score == 9.8
    assert source == 'NVD-CVSSv3.1'


def test_cvss_falls_back_to_v20_when_nothing_newer_present():
    metrics = {'cvssMetricV2': [{'cvssData': {'baseScore': 5.0}}]}
    score, source = cvss_engine._extract_best_cvss(metrics)
    assert score == 5.0
    assert source == 'NVD-CVSSv2.0'


def test_pci_compliance_status_threshold_is_exactly_4_0():
    """PCI reference doc §7: CVSS >= 4.0 is Fail, below is Pass."""
    assert cvss_engine.pci_compliance_status(3.9, False) == 'Pass'
    assert cvss_engine.pci_compliance_status(4.0, False) == 'Fail'


def test_auto_fail_overrides_a_low_cvss_score():
    assert cvss_engine.pci_compliance_status(0.0, True) == 'Fail'


def test_resolve_cvss_caches_after_first_nvd_lookup(app, db):
    from models import CveCache

    with patch('cvss_engine.fetch_nvd_cvss', return_value=(9.8, 'NVD-CVSSv3.1')) as mock_fetch:
        score, source = cvss_engine.resolve_cvss('CVE-2021-44228', db, CveCache, severity_hint='High')
        assert score == 9.8
        assert mock_fetch.call_count == 1

    # Second lookup for the SAME CVE must hit the cache, not the network.
    with patch('cvss_engine.fetch_nvd_cvss', side_effect=AssertionError("must not hit network on cache hit")):
        score2, source2 = cvss_engine.resolve_cvss('CVE-2021-44228', db, CveCache, severity_hint='High')
        assert score2 == 9.8
        assert source2 == 'NVD-CVSSv3.1'


def test_resolve_cvss_falls_back_to_severity_band_when_no_cve(app, db):
    from models import CveCache
    score, source = cvss_engine.resolve_cvss('', db, CveCache, severity_hint='Medium')
    assert score == 4.0
    assert source == 'tool-severity-fallback'
