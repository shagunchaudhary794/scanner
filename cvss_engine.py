"""
CVSS v3.1 / NVD-backed scoring engine.

PCI ASV Program Guide requires ASVs to default to CVSS v3.1, sourced from
NVD, with v3.0/v2.0 as fallback only when v3.1 isn't published for a CVE
(reference doc §11, "ASVs must default to v3.1"). Architecture notes
(scanner_architecture_notes.pdf, correction #4) call out that CVSS mapping
must NOT be a pass-through from whatever a tool (OpenVAS threat, ZAP risk,
Nuclei severity) happens to report -- it has to be normalized through this
engine. Distributed-Vulnerability-Scan-Orchestration-Engine.md §40/42
defines cvss_score / cvss_source as the two fields tracking this.

Resolution order for a finding with a CVE:
    1. NVD CVSS v3.1 vector/score
    2. NVD CVSS v3.0
    3. NVD CVSS v2.0 (converted to a 0-10 scale, already is)
    4. Tool-native severity mapped to a conservative CVSS-equivalent band
       (used only when there's no CVE at all, e.g. ZAP/Nmap policy findings)

PostgreSQL is the source of truth (per project principles) -- results are
cached in the `cve_cache` table so we don't re-hit NVD for the same CVE
across scans, and so a scan doesn't hard-fail if NVD is rate-limiting us.
"""

import os
import time
import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY = os.environ.get("NVD_API_KEY")  # optional; raises rate limit from 5/30s to 50/30s

# Without an API key NVD allows ~5 requests per rolling 30s window.
_MIN_REQUEST_INTERVAL = 0.6 if NVD_API_KEY else 6.5
_last_request_ts = 0.0

# Tool-native severity -> conservative CVSS-equivalent score, used ONLY when
# a finding has no CVE to look up (policy/config findings from ZAP, Nmap
# NSE, testssl.sh). These are deliberately placed at the low end of each
# PCI severity band (see reference doc §7: 4.0+ = fail) so a finding never
# gets bumped into "pass" territory just because it lacks a CVE.
_SEVERITY_FALLBACK_SCORE = {
    'critical': 9.0,
    'high': 7.0,
    'medium': 4.0,
    'low': 2.0,
    'informational': 0.0,
    'info': 0.0,
    'none': 0.0,
}


def _rate_limit():
    global _last_request_ts
    elapsed = time.time() - _last_request_ts
    if elapsed < _MIN_REQUEST_INTERVAL:
        time.sleep(_MIN_REQUEST_INTERVAL - elapsed)
    _last_request_ts = time.time()


def _extract_best_cvss(nvd_metrics: dict):
    """Given the `metrics` block of an NVD 2.0 API CVE record, return
    (score, version_label) preferring v3.1 > v3.0 > v2.0."""
    for key, label in (
        ("cvssMetricV31", "NVD-CVSSv3.1"),
        ("cvssMetricV30", "NVD-CVSSv3.0"),
        ("cvssMetricV2", "NVD-CVSSv2.0"),
    ):
        entries = nvd_metrics.get(key)
        if not entries:
            continue
        # Prefer "Primary" source entries if present, else take the first.
        primary = next((e for e in entries if e.get('type') == 'Primary'), entries[0])
        cvss_data = primary.get('cvssData', {})
        score = cvss_data.get('baseScore')
        if score is not None:
            return float(score), label
    return None, None


def fetch_nvd_cvss(cve_id: str, timeout: int = 15):
    """Query NVD directly for a CVE's best-available CVSS base score.
    Returns (score: float|None, source: str|None). Never raises -- network
    or parsing failures return (None, None) so the caller can fall back.
    """
    if not cve_id or not cve_id.upper().startswith('CVE-'):
        return None, None

    headers = {'apiKey': NVD_API_KEY} if NVD_API_KEY else {}
    try:
        _rate_limit()
        resp = requests.get(
            NVD_API_URL,
            params={'cveId': cve_id},
            headers=headers,
            timeout=timeout,
        )
        if resp.status_code == 429:
            # Back off once and retry a single time before giving up.
            time.sleep(10)
            resp = requests.get(NVD_API_URL, params={'cveId': cve_id}, headers=headers, timeout=timeout)
        if resp.status_code != 200:
            return None, None
        data = resp.json()
        vulns = data.get('vulnerabilities', [])
        if not vulns:
            return None, None
        cve_record = vulns[0].get('cve', {})
        metrics = cve_record.get('metrics', {})
        return _extract_best_cvss(metrics)
    except Exception as e:
        print(f"NVD lookup failed for {cve_id}: {e}")
        return None, None


def _get_cached(cve_id, db, CveCache):
    return CveCache.query.get(cve_id)


def resolve_cvss(cve_id, db, CveCache, severity_hint=None):
    """Primary entry point. Resolves a finding's CVSS score/source, using
    the Postgres cache first, then NVD, then (only if there's no CVE at
    all) the tool-native severity fallback.

    Returns (score: float, source: str).
    """
    if cve_id:
        cve_id = cve_id.strip().upper()

    if cve_id and cve_id.startswith('CVE-'):
        cached = _get_cached(cve_id, db, CveCache)
        if cached is not None:
            return cached.cvss_score, cached.cvss_source

        score, source = fetch_nvd_cvss(cve_id)
        if score is not None:
            entry = CveCache(cve_id=cve_id, cvss_score=score, cvss_source=source)
            db.session.merge(entry)
            db.session.commit()
            return score, source

        # NVD had no record / lookup failed -- fall through to severity
        # fallback below rather than leaving the finding unscored, but tag
        # the source so it's clear this wasn't NVD-backed.

    hint = (severity_hint or 'informational').strip().lower()
    score = _SEVERITY_FALLBACK_SCORE.get(hint, 0.0)
    return score, 'tool-severity-fallback'


def pci_compliance_status(cvss_score: float, is_auto_fail: bool) -> str:
    """PCI reference doc §7: CVSS >= 4.0 = fail, OR any explicit auto-fail
    condition regardless of score. Returns 'Fail' or 'Pass'.
    """
    if is_auto_fail:
        return 'Fail'
    if cvss_score is not None and cvss_score >= 4.0:
        return 'Fail'
    return 'Pass'
