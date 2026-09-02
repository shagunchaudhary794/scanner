"""Detection logic added on top of the tool integrations: testssl.sh
Special Notes (§6.2), unknown-service handling (§6.7), payment-page
scripts (§6.5), inconclusive-scan detection (§6.8/§7), and load-balancer
detection (§5.5)."""
import json
from unittest.mock import patch, MagicMock
import tasks


def _seed(db):
    from models import Organization, Asset, Scan
    org = Organization(name='DetectionTestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, hostname='target.example.com', ip_address='203.0.113.10')
    db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='running')
    db.session.add(scan); db.session.commit()
    return scan.id, asset.id


# --- testssl.sh Special Notes (§6.2) ---------------------------------------

def test_testssl_captures_adh_and_sha1_special_notes_not_just_critical_high(app, db):
    """Regression guard: ADH and SHA-1 are typically MEDIUM/LOW in
    testssl's own scale -- a naive CRITICAL/HIGH-only filter silently
    drops them entirely."""
    from models import Finding
    scan_id, asset_id = _seed(db)

    fake_output = [
        {"id": "TLS1_1", "severity": "HIGH", "finding": "TLS 1.1 offered"},
        {"id": "cipher_negotiated", "severity": "MEDIUM", "finding": "AECDH-AES256-SHA offered (NOT ok): anonymous ADH cipher"},
        {"id": "cert_signatureAlgorithm", "severity": "LOW", "finding": "Certificate uses SHA1WithRSA -- SHA-1 signature offered"},
        {"id": "cert_expiration", "severity": "OK", "finding": "expires in 145 days -- not vulnerable"},
        {"id": "some_other_check", "severity": "INFO", "finding": "TLS 1.3 not offered"},
    ]

    def fake_subprocess(cmd, **kwargs):
        json_path = cmd[cmd.index('--jsonfile') + 1]
        with open(json_path, 'w') as f:
            json.dump(fake_output, f)
        return MagicMock(returncode=0, stdout='')

    with patch('subprocess.run', side_effect=fake_subprocess):
        tasks._run_testssl_scan(scan_id, asset_id, 'target.example.com',
                                 [{'port': 443, 'proto': 'tcp', 'service': 'https'}], db, Finding)

    findings = Finding.query.filter_by(scan_id=scan_id, source_tool='testssl').all()
    assert len(findings) == 3  # TLS1.1 auto-fail + ADH + SHA-1

    tls = next((f for f in findings if 'TLS1_1' in f.description), None)
    assert tls is not None and tls.is_auto_fail is True and tls.severity == 'High'

    adh = next((f for f in findings if 'Anonymous' in f.description), None)
    assert adh is not None and adh.is_auto_fail is False and adh.severity == 'Medium'
    assert '§6.2' in adh.description

    sha1 = next((f for f in findings if 'SHA-1' in f.description and 'Anonymous' not in f.description), None)
    assert sha1 is not None and sha1.is_auto_fail is False

    # The negative/clean entry must produce nothing.
    assert not any('cert_expiration' in f.description for f in findings)


# --- Unknown-service handling (§6.7) ---------------------------------------

def test_unknown_and_tcpwrapped_and_missing_service_flagged_recognized_service_not(app, db):
    from models import Finding
    scan_id, asset_id = _seed(db)

    fake_xml = '''<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
<port protocol="tcp" portid="31337"><state state="open"/><service name="unknown"/></port>
<port protocol="tcp" portid="8888"><state state="open"/></port>
<port protocol="tcp" portid="445"><state state="open"/><service name="tcpwrapped"/></port>
</ports>
</host>
</nmaprun>'''

    def fake_subprocess(cmd, **kwargs):
        xml_path = cmd[cmd.index('-oX') + 1]
        with open(xml_path, 'w') as f:
            f.write(fake_xml)
        return MagicMock(returncode=0, stdout='')

    with patch('subprocess.run', side_effect=fake_subprocess):
        open_ports = tasks._run_nmap_scan(scan_id, asset_id, 'target.example.com', db, Finding)

    assert len(open_ports) == 4

    unknown_findings = Finding.query.filter_by(scan_id=scan_id, source_tool='nmap').filter(
        Finding.description.like('%Unknown service%')
    ).all()
    ports_flagged = sorted(int(f.description.split('port ')[1].split('/')[0]) for f in unknown_findings)
    assert ports_flagged == [445, 8888, 31337]
    assert 80 not in ports_flagged

    for f in unknown_findings:
        assert f.severity == 'Low'
        assert f.is_auto_fail is False


# --- Inconclusive-scan detection (§6.8/§7) ---------------------------------

def test_heavy_port_filtering_triggers_inconclusive_scan_auto_fail(app, db):
    from models import Finding, ScanJob
    scan_id, asset_id = _seed(db)
    job = ScanJob(scan_id=scan_id, asset_id=asset_id, status='running')
    db.session.add(job); db.session.commit()

    ports_xml = []
    for i in range(1, 146):
        ports_xml.append(f'<port protocol="tcp" portid="{i}"><state state="filtered"/></port>')
    for i in range(146, 151):
        ports_xml.append(f'<port protocol="tcp" portid="{i}"><state state="open"/><service name="http"/></port>')

    fake_xml = f'''<?xml version="1.0"?>
<nmaprun><host><status state="up"/><ports>{''.join(ports_xml)}</ports></host></nmaprun>'''

    def fake_subprocess(cmd, **kwargs):
        xml_path = cmd[cmd.index('-oX') + 1]
        with open(xml_path, 'w') as f:
            f.write(fake_xml)
        return MagicMock(returncode=0, stdout='')

    with patch('subprocess.run', side_effect=fake_subprocess):
        open_ports = tasks._run_nmap_scan(scan_id, asset_id, 'target.example.com', db, Finding)

    assert len(open_ports) == 5  # open ports still correctly extracted

    finding = Finding.query.filter_by(scan_id=scan_id, asset_id=asset_id).filter(
        Finding.description.like('%Inconclusive scan%')
    ).first()
    assert finding is not None
    assert finding.is_auto_fail is True
    assert finding.severity == 'High'

    db.session.expire_all()
    job = ScanJob.query.get(job.id)
    assert job.is_inconclusive is True


def test_normal_host_does_not_trigger_inconclusive_scan_false_positive(app, db):
    from models import Finding
    scan_id, asset_id = _seed(db)

    ports_xml = []
    for i in range(1, 101):
        state = 'open' if i in (22, 80, 443) else 'closed'
        svc = '<service name="ssh"/>' if i == 22 else ('<service name="http"/>' if i == 80 else ('<service name="https"/>' if i == 443 else ''))
        ports_xml.append(f'<port protocol="tcp" portid="{i}"><state state="{state}"/>{svc}</port>')

    fake_xml = f'''<?xml version="1.0"?>
<nmaprun><host><status state="up"/><ports>{''.join(ports_xml)}</ports></host></nmaprun>'''

    def fake_subprocess(cmd, **kwargs):
        xml_path = cmd[cmd.index('-oX') + 1]
        with open(xml_path, 'w') as f:
            f.write(fake_xml)
        return MagicMock(returncode=0, stdout='')

    with patch('subprocess.run', side_effect=fake_subprocess):
        tasks._run_nmap_scan(scan_id, asset_id, 'target.example.com', db, Finding)

    finding = Finding.query.filter_by(scan_id=scan_id, asset_id=asset_id).filter(
        Finding.description.like('%Inconclusive scan%')
    ).first()
    assert finding is None


# --- Payment page script detection (§6.5) ----------------------------------

def test_known_trackers_flagged_first_party_script_not(app, db):
    from models import Finding
    scan_id, asset_id = _seed(db)

    fake_scripts = [
        'https://target.example.com/assets/app.js',
        'https://www.googletagmanager.com/gtm.js?id=GTM-XXXX',
        'https://connect.facebook.net/en_US/fbevents.js',
    ]

    mock_page = MagicMock()
    mock_page.eval_on_selector_all.return_value = fake_scripts
    mock_browser = MagicMock()
    mock_browser.new_page.return_value = mock_page
    mock_playwright_ctx = MagicMock()
    mock_playwright_ctx.chromium.launch.return_value = mock_browser

    with patch('playwright.sync_api.sync_playwright') as mock_sync_playwright:
        mock_sync_playwright.return_value.__enter__.return_value = mock_playwright_ctx
        tasks._run_payment_script_check(scan_id, asset_id, 'target.example.com',
                                         [{'port': 443, 'proto': 'tcp', 'service': 'https'}], db, Finding)

    findings = Finding.query.filter_by(scan_id=scan_id, source_tool='payment-script-check').all()
    assert len(findings) == 2

    hosts_found = {f.description.split(': ')[1].split(' (')[0] for f in findings}
    assert 'www.googletagmanager.com' in hosts_found
    assert 'connect.facebook.net' in hosts_found
    assert not any('app.js' in f.description for f in findings)

    for f in findings:
        assert f.severity == 'Low'
        assert f.is_auto_fail is False
        assert '§6.5' in f.description


def test_payment_script_check_skips_gracefully_without_playwright(app, db, monkeypatch):
    """_run_payment_script_check does `from playwright.sync_api import
    sync_playwright` locally inside a try/except ImportError -- simulate
    that import genuinely failing by removing the module from sys.modules
    and making it unimportable, rather than patching Python's global
    import machinery (which is broader than the module actually needs)."""
    from models import Finding
    import sys
    scan_id, asset_id = _seed(db)

    real_import = __builtins__['__import__'] if isinstance(__builtins__, dict) else __builtins__.__import__

    def blocking_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == 'playwright.sync_api' or (name == 'playwright' and fromlist and 'sync_api' in fromlist):
            raise ImportError("simulated: playwright not installed")
        return real_import(name, globals, locals, fromlist, level)

    with patch('builtins.__import__', side_effect=blocking_import):
        tasks._run_payment_script_check(scan_id, asset_id, 'target.example.com',
                                         [{'port': 443, 'proto': 'tcp', 'service': 'https'}], db, Finding)

    # Must not raise, and must not create any findings.
    assert Finding.query.filter_by(scan_id=scan_id, source_tool='payment-script-check').count() == 0


# --- Load balancer detection (§5.5), real DNS ------------------------------

def test_load_balancer_detected_on_a_real_multi_a_record_host(app, db):
    from models import Finding
    scan_id, asset_id = _seed(db)

    # pypi.org (in the sandbox's network allowlist) genuinely has
    # multiple A records -- a real assertion about real DNS.
    tasks._check_load_balancer(scan_id, asset_id, 'pypi.org', db, Finding)

    finding = Finding.query.filter_by(scan_id=scan_id, asset_id=asset_id, source_tool='discovery').first()
    assert finding is not None
    assert finding.is_auto_fail is False
    assert finding.severity == 'Low'
    assert '§5.5' in finding.description


def test_load_balancer_not_flagged_on_a_real_single_ip_host(app, db):
    from models import Finding
    scan_id, asset_id = _seed(db)

    tasks._check_load_balancer(scan_id, asset_id, 'codeload.github.com', db, Finding)

    finding = Finding.query.filter_by(scan_id=scan_id, asset_id=asset_id, source_tool='discovery').first()
    assert finding is None
