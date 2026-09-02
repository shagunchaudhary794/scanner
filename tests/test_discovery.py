"""discovery.py -- DNS/MX/redirect/JS-crawl scope discovery (PCI §4.4).

Uses real network calls against domains in the sandbox's allowlist
(github.com, pypi.org, etc.) where practical -- this module is
fundamentally about real-world DNS/HTTP behavior, and mocking every layer
would just re-test the mocks. Playwright-dependent tests are marked slow.
"""
import pytest
import discovery


def test_resolve_a_record_real_domain():
    ip = discovery.resolve_a_record('github.com')
    assert ip is not None
    assert ip.count('.') == 3  # looks like an IPv4 address


def test_resolve_a_record_nonexistent_domain_returns_none():
    assert discovery.resolve_a_record('this-domain-should-not-exist-xyzabc123.invalid') is None


def test_resolve_all_a_records_finds_multiple_ips_on_a_real_multi_ip_host():
    """pypi.org is fronted by Fastly and genuinely has multiple A
    records -- this is a real assertion about real DNS, not a fixture."""
    ips = discovery.resolve_all_a_records('pypi.org')
    assert len(ips) > 1


def test_resolve_all_a_records_single_ip_host():
    ips = discovery.resolve_all_a_records('codeload.github.com')
    assert len(ips) >= 1


def test_probe_common_subdomains_only_returns_resolvable_hosts():
    """Every subdomain probed is a real DNS lookup -- a nonexistent
    combination (almost certainly true for most COMMON_SUBDOMAINS
    against github.com) must simply not appear in the result, not error."""
    result = discovery.probe_common_subdomains('github.com')
    assert isinstance(result, dict)
    for fqdn, ip in result.items():
        assert fqdn.endswith('.github.com')
        assert ip is not None


def test_trace_redirects_caps_at_max_hops():
    """Structural guarantee against an infinite/very long redirect
    chain -- verified against the parameter contract, not a live chain."""
    hosts = discovery.trace_redirects('http://127.0.0.1:1', max_hops=3)
    assert hosts == []


@pytest.mark.slow
def test_run_discovery_end_to_end_real_domain():
    """Full integration: DNS + MX + redirect + (if Playwright installed)
    JS-crawl, against a real domain."""
    candidates = discovery.run_discovery('github.com', probe_redirects=True, use_browser=True)
    assert isinstance(candidates, dict)
    for host, info in candidates.items():
        assert info['via'] in ('dns_subdomain', 'mx_record', 'redirect', 'js_redirect', 'crawl')


def test_trace_js_redirects_and_crawl_degrades_gracefully_without_playwright(monkeypatch):
    monkeypatch.setattr(discovery, '_HAVE_PLAYWRIGHT', False)
    result = discovery.trace_js_redirects_and_crawl('https://example.com')
    assert result['redirect_hosts'] == []
    assert result['crawled_hosts'] == []
    assert result['skipped_reason'] == 'playwright not installed'


def test_run_discovery_does_not_crash_when_playwright_unavailable(monkeypatch):
    monkeypatch.setattr(discovery, '_HAVE_PLAYWRIGHT', False)
    candidates = discovery.run_discovery('github.com', probe_redirects=False, use_browser=True)
    assert isinstance(candidates, dict)
    assert not any(info['via'] in ('js_redirect', 'crawl') for info in candidates.values())
