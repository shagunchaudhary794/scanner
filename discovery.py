"""
Discovery / scope validation.

PCI reference doc §4.4 (Discovery Requirements) -- exact bullet list:
    1. Lookup the IP address for each provided domain to determine if it
       was disclosed.
    2. Perform DNS forward and reverse lookups of common host names (e.g.
       "www," "mail") not provided by the customer.
    3. Identify IP addresses found during MX record DNS lookups.
    4. Track and identify IP addresses outside of scope reached via web
       redirects (including JavaScript, Meta redirects, and HTTP 30x
       codes).
    5. Match domains found during website crawling to the user-supplied
       domains.
    6. Report any components found but excluded by the customer on the
       Attestation of Scan Compliance.

This module implements all six points. Point 4's HTTP 30x/meta-refresh
half is handled by trace_redirects() using plain requests; the
JavaScript-redirect half needs a real browser to execute page JS, so
trace_js_redirects_and_crawl() uses a headless Chromium (Playwright) for
that plus a single-level, same-origin crawl for point 5. Both degrade
gracefully (return empty results, not an exception) if Playwright or its
browser binary isn't installed -- see run_discovery(use_browser=...).
Point 6 (reporting excluded-but-found components) is handled at the
route/model layer via Asset.is_out_of_scope + segmentation_attestation,
not here.

Every check here is read-only DNS/HTTP -- no port scanning, no exploit
attempts -- consistent with this being a pre-scan scoping step, not the
scan itself.
"""

import socket
import re
import requests

try:
    import dns.resolver
    import dns.reversename
    _HAVE_DNSPYTHON = True
except ImportError:
    _HAVE_DNSPYTHON = False

TIMEOUT = 5

# §4.4 point 2: "common host names (e.g. www, mail)". This list is
# deliberately short and non-exhaustive -- it's meant to catch commonly
# forgotten Internet-facing assets, not to be a full subdomain wordlist
# scan (which would blur into reconnaissance the customer didn't scope).
COMMON_SUBDOMAINS = [
    'www', 'mail', 'webmail', 'ftp', 'remote', 'vpn', 'autodiscover',
    'admin', 'portal', 'api', 'dev', 'staging', 'test', 'secure', 'shop',
]

MAX_REDIRECT_HOPS = 10


def resolve_a_record(hostname):
    """§4.4 point 1: resolve a customer-provided domain's IP so it's on
    record as disclosed. Returns IP string or None."""
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        return None


def reverse_lookup(ip):
    """§4.4 point 2 (reverse half). Returns PTR hostname or None."""
    if _HAVE_DNSPYTHON:
        try:
            rev_name = dns.reversename.from_address(ip)
            answer = dns.resolver.resolve(rev_name, 'PTR', lifetime=TIMEOUT)
            return str(answer[0]).rstrip('.')
        except Exception:
            return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror):
        return None


def probe_common_subdomains(domain):
    """§4.4 point 2 (forward half): DNS forward lookups of common host
    names not provided by the customer. Returns {fqdn: ip} for every
    subdomain that actually resolves.
    """
    found = {}
    for sub in COMMON_SUBDOMAINS:
        fqdn = f"{sub}.{domain}"
        ip = resolve_a_record(fqdn)
        if ip:
            found[fqdn] = ip
    return found


def mx_lookup(domain):
    """§4.4 point 3: identify IP addresses found during MX record
    lookups. Returns list of {'mx_host': str, 'ip': str|None}.
    """
    results = []
    if not _HAVE_DNSPYTHON:
        return results
    try:
        answers = dns.resolver.resolve(domain, 'MX', lifetime=TIMEOUT)
        for rdata in answers:
            mx_host = str(rdata.exchange).rstrip('.')
            results.append({'mx_host': mx_host, 'ip': resolve_a_record(mx_host)})
    except Exception:
        pass
    return results


_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^;]+;\s*url=([^"\']+)',
    re.IGNORECASE,
)


def trace_redirects(url, max_hops=MAX_REDIRECT_HOPS):
    """§4.4 point 4 (HTTP 30x + meta-refresh portion only -- see module
    docstring for the JS-redirect limitation). Follows a redirect chain
    starting at `url`, one hop at a time, and returns the list of
    distinct hostnames encountered along the way (excluding the starting
    host). Each hop is a single non-disruptive GET.
    """
    from urllib.parse import urlparse, urljoin

    seen_hosts = set()
    start_host = urlparse(url).hostname
    current = url

    for _ in range(max_hops):
        try:
            resp = requests.get(current, timeout=TIMEOUT, allow_redirects=False, verify=False)
        except Exception:
            break

        next_url = None
        if resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get('Location')
            if location:
                next_url = urljoin(current, location)
        elif resp.status_code == 200:
            match = _META_REFRESH_RE.search(resp.text[:20000])
            if match:
                next_url = urljoin(current, match.group(1).strip())

        if not next_url:
            break

        host = urlparse(next_url).hostname
        if host and host != start_host:
            seen_hosts.add(host)
        current = next_url

    return sorted(seen_hosts)


try:
    from playwright.sync_api import sync_playwright
    _HAVE_PLAYWRIGHT = True
except ImportError:
    _HAVE_PLAYWRIGHT = False

MAX_CRAWL_LINKS = 20
BROWSER_TIMEOUT_MS = 15000


def trace_js_redirects_and_crawl(start_url, max_links=MAX_CRAWL_LINKS):
    """§4.4 point 4 (the JS-redirect half that trace_redirects() above
    can't do) and point 5 (crawling): loads the page in a real headless
    browser so `window.location = ...` / `location.href = ...`
    JavaScript redirects actually execute, then does a single-level,
    same-origin-only link crawl of whatever page it lands on.

    Returns {'redirect_hosts': [...], 'crawled_hosts': [...]} -- empty
    lists (not an exception) if Playwright/its browser isn't installed,
    since this is meant to degrade gracefully alongside the DNS/MX/30x
    checks in run_discovery(), not block them.

    This is intentionally shallow -- ONE hop of JS redirect, ONE level
    of links from the landing page, capped at max_links. A real crawler
    (multi-level, respecting robots.txt, deduplicating a full site graph)
    is a materially different and heavier tool; going further here would
    blur into reconnaissance the customer didn't explicitly scope, which
    is the same boundary the rest of this module already draws.
    """
    if not _HAVE_PLAYWRIGHT:
        return {'redirect_hosts': [], 'crawled_hosts': [], 'skipped_reason': 'playwright not installed'}

    from urllib.parse import urlparse

    start_host = urlparse(start_url).hostname
    redirect_hosts = set()
    crawled_hosts = set()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch()
            try:
                page = browser.new_page()
                page.on('framenavigated', lambda frame: (
                    redirect_hosts.add(urlparse(frame.url).hostname)
                    if frame.url and urlparse(frame.url).hostname
                    and urlparse(frame.url).hostname != start_host else None
                ))
                page.goto(start_url, timeout=BROWSER_TIMEOUT_MS, wait_until='networkidle')

                # Single-level, same-origin link harvest from wherever we
                # actually landed (post any JS redirect chain).
                landed_host = urlparse(page.url).hostname
                hrefs = page.eval_on_selector_all('a[href]', 'els => els.map(e => e.href)')
                for href in hrefs[:max_links * 3]:  # oversample before host-filtering
                    host = urlparse(href).hostname
                    if host and host != landed_host and host != start_host:
                        crawled_hosts.add(host)
                    if len(crawled_hosts) >= max_links:
                        break
            finally:
                browser.close()
    except Exception as e:
        return {'redirect_hosts': [], 'crawled_hosts': [], 'skipped_reason': str(e)}

    redirect_hosts.discard(None)
    crawled_hosts.discard(None)
    return {'redirect_hosts': sorted(redirect_hosts), 'crawled_hosts': sorted(crawled_hosts)}


def run_discovery(domain, probe_redirects=True, use_browser=True):
    """Aggregates all discovery checks for one customer-provided domain.
    Returns a dict of candidate hostnames -> {'ip': str|None, 'via': str}
    for anything found that ISN'T the domain itself, ready to be shown to
    the customer for confirmation before being added to scope (§4.4 point
    6 / Phase 1 Scoping in the reference doc: 'If the ASV finds hidden
    components not listed by the customer, they must consult the
    customer').
    """
    candidates = {}

    for fqdn, ip in probe_common_subdomains(domain).items():
        candidates[fqdn] = {'ip': ip, 'via': 'dns_subdomain'}

    for mx in mx_lookup(domain):
        if mx['mx_host'] and mx['mx_host'] != domain:
            candidates[mx['mx_host']] = {'ip': mx['ip'], 'via': 'mx_record'}

    if probe_redirects:
        for scheme in ('https', 'http'):
            try:
                hosts = trace_redirects(f"{scheme}://{domain}")
            except Exception:
                hosts = []
            for host in hosts:
                if host not in candidates:
                    candidates[host] = {'ip': resolve_a_record(host), 'via': 'redirect'}

    if use_browser:
        # §4.4 point 4 (JS redirects) and point 5 (crawling) -- the parts
        # trace_redirects() above structurally can't do since it never
        # executes page JavaScript. Best-effort: if Playwright/its browser
        # binary isn't installed, this silently contributes nothing rather
        # than failing the whole discovery pass (see module docstring).
        for scheme in ('https', 'http'):
            try:
                browser_results = trace_js_redirects_and_crawl(f"{scheme}://{domain}")
            except Exception:
                browser_results = {'redirect_hosts': [], 'crawled_hosts': []}
            for host in browser_results.get('redirect_hosts', []):
                if host not in candidates:
                    candidates[host] = {'ip': resolve_a_record(host), 'via': 'js_redirect'}
            for host in browser_results.get('crawled_hosts', []):
                if host not in candidates:
                    candidates[host] = {'ip': resolve_a_record(host), 'via': 'crawl'}

    return candidates
