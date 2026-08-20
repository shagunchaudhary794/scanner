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

This module implements 1, 2, 3, and the HTTP-30x/meta-refresh portion of
4. It deliberately does NOT implement JavaScript-redirect tracking or
full-site crawling (5) -- both require a headless browser / crawler,
which is a materially bigger dependency than DNS lookups and raw HTTP
requests, and is flagged as a known gap rather than silently skipped.
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


def run_discovery(domain, probe_redirects=True):
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

    return candidates
