import os
import json
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime

import requests
from celery import Celery
from config import Config

# Initialize Celery app
celery = Celery(
    'tasks',
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND
)

# Ports treated as web (ZAP candidates) / TLS (testssl.sh candidates) when Nmap
# doesn't resolve a service name for them.
WEB_PORTS = {80, 443, 8080, 8443}
TLS_PORTS = {443, 8443}

# PCI DSS Req 1.4.4 / §6.6: databases must not be directly reachable from the
# Internet. Any of these open on an external asset is an automatic failure.
DB_PORTS = {3306, 5432, 1433, 27017, 6379, 1521}

# PCI DSS §6.4: remote administration services visible to the Internet require
# a Special Note (Telnet specifically transmits credentials in cleartext).
REMOTE_ADMIN_SERVICES = {'ssh', 'telnet', 'rdp', 'vnc', 'ms-wbt-server', 'pcanywhere'}


@celery.task
def execute_scan(scan_id, scan_type, asset_ids):
    from app import create_app, db
    from models import Scan, Finding, Asset

    app = create_app()
    with app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return

        scan.status = 'running'
        scan.progress = 'Initializing scan...'
        scan.progress_percent = 5
        scan.start_time = datetime.utcnow()
        db.session.commit()

        try:
            for asset_id in asset_ids:
                asset = Asset.query.get(asset_id)
                if not asset:
                    continue

                target = asset.ip_address or asset.hostname
                if not target:
                    continue

                # Nmap always runs first. It's the baseline discovery layer:
                # host/port/service/OS fingerprinting (PCI §5.1-5.3), and every
                # downstream tool below targets the ports it finds.
                open_ports = _run_nmap_scan(scan.id, asset_id, target, db, Finding)

                if scan_type == 'external':
                    # PCI DSS 11.3.2 external scan pipeline.
                    _run_testssl_scan(scan.id, asset_id, target, open_ports, db, Finding)
                    _run_zap_scan(scan.id, asset_id, target, open_ports, db, Finding)
                    _run_nuclei_scan(scan.id, asset_id, target, db, Finding)
                    _run_openvas_scan(scan.id, asset_id, target, db, Finding)
                else:
                    # Internal scan: adds product value, does not itself satisfy
                    # the external ASV requirement (11.3.2), so TLS/web-app
                    # checks are skipped here — same as the architecture doc.
                    _run_openvas_scan(scan.id, asset_id, target, db, Finding)
                    _run_nuclei_scan(scan.id, asset_id, target, db, Finding)

            scan.progress_percent = 100
            scan.progress = 'Completed'
            scan.status = 'completed'
        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Error executing scan {scan_id}:\n{error_trace}")
            scan.status = 'failed'
            scan.error_message = f"{str(e)}\n\nTraceback:\n{error_trace}"
            scan.progress = 'Failed'
        finally:
            # Check findings
            if scan.status == 'completed' and not scan.findings:
                scan.progress = 'Completed successfully (0 vulnerabilities found)'

            scan.end_time = datetime.utcnow()
            db.session.commit()


def _resolve_nuclei_binary():
    import shutil
    exe = shutil.which('nuclei') or shutil.which('nuclei.exe')
    if not exe:
        return 'nuclei'
    head = os.path.dirname(exe)
    if os.path.basename(head).lower() == 'shims':
        candidate = os.path.join(head, 'apps', 'nuclei', 'current', 'nuclei.exe')
        if os.path.isfile(candidate):
            return candidate
    return exe


def _run_nuclei_scan(scan_id, asset_id, target, db, Finding):
    from models import Scan
    scan = Scan.query.get(scan_id)
    scan.progress = f"Running Nuclei on {target}..."
    scan.progress_percent = 60
    db.session.commit()

    cmd = [
        _resolve_nuclei_binary(),
        '-u', target,
        '-tags', 'cve,misconfig',
        '-severity', 'critical,high,medium',
        '-j',
        '-silent'
    ]

    try:
        # Use stderr=subprocess.STDOUT to capture all output
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)

        if result.returncode != 0:
            raise Exception(f"Nuclei exited with code {result.returncode}:\n{result.stdout}")

        scan.progress = f"Parsing Nuclei results for {target}..."
        scan.progress_percent = 80
        db.session.commit()

        for line in result.stdout.splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                info = data.get('info', {})
                severity_raw = info.get('severity', 'informational').title()

                # Normalize severity
                if severity_raw in ['Critical', 'High', 'Medium', 'Low']:
                    severity = severity_raw
                else:
                    severity = 'Informational'

                finding = Finding(
                    scan_id=scan.id,
                    asset_id=asset_id,
                    severity=severity,
                    cve=info.get('classification', {}).get('cve-id', ''),
                    description=info.get('description') or info.get('name') or 'Nuclei finding',
                    recommendation=info.get('remediation', ''),
                    source_tool='nuclei',
                    is_auto_fail=False
                )
                db.session.add(finding)
            except json.JSONDecodeError:
                pass

        db.session.commit()
    except subprocess.TimeoutExpired as e:
        print(f"Nuclei scan timed out for {target}")
        raise e
    except Exception as e:
        print(f"Nuclei error: {e}")
        raise e


def _run_nmap_scan(scan_id, asset_id, target, db, Finding):
    """Baseline discovery layer (PCI §5.1-5.3): live host, full TCP port range,
    service/version detection, OS fingerprinting, and NSE vuln + DNS
    zone-transfer scripts. Returns the list of open ports so downstream tools
    (testssl.sh, ZAP) know what to target instead of re-discovering it.
    """
    from models import Scan
    scan = Scan.query.get(scan_id)
    scan.progress = f"Running Nmap discovery on {target}..."
    scan.progress_percent = 10
    db.session.commit()

    tmp = tempfile.NamedTemporaryFile(suffix='.xml', delete=False)
    xml_path = tmp.name
    tmp.close()

    # -p- scans the full TCP range (PCI 5.2 requires all TCP ports, not a
    # sample), which is slow on top of -sV/-O/--script. 30-minute timeout
    # below reflects that; narrow -p- if that's too slow for your dev loop.
    cmd = [
        'nmap', '-Pn', '-sV', '-O',
        '--script', 'vuln,dns-zone-transfer',
        '-p-', '-oX', xml_path, target
    ]

    open_ports = []
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=1800)
        if result.returncode != 0:
            raise Exception(f"Nmap exited with code {result.returncode}:\n{result.stdout}")

        scan.progress = f"Parsing Nmap results for {target}..."
        scan.progress_percent = 20
        db.session.commit()

        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall('host'):
            os_match = host.find('.//osmatch')
            os_name = os_match.get('name') if os_match is not None else None

            for port_el in host.findall('.//port'):
                state = port_el.find('state')
                if state is None or state.get('state') != 'open':
                    continue

                port_id = int(port_el.get('portid'))
                proto = port_el.get('protocol')
                service_el = port_el.find('service')
                service_name = service_el.get('name') if service_el is not None else 'unknown'

                open_ports.append({'port': port_id, 'proto': proto, 'service': service_name})

                # PCI 1.4.4 / §6.6 — databases exposed to the Internet: auto-fail
                if port_id in DB_PORTS:
                    db.session.add(Finding(
                        scan_id=scan.id, asset_id=asset_id, severity='High', cve='',
                        description=(
                            f"Database service ({service_name}) exposed on port {port_id}/{proto}. "
                            f"Open access to system components storing cardholder data from the "
                            f"Internet violates PCI DSS Requirement 1.4.4."
                        ),
                        recommendation="Restrict database access to internal networks only; place behind a firewall/NSC.",
                        source_tool='nmap', is_auto_fail=True
                    ))

                # PCI §6.4 — remote admin services visible to the Internet: Special Note
                if service_name in REMOTE_ADMIN_SERVICES:
                    is_telnet = service_name == 'telnet'
                    db.session.add(Finding(
                        scan_id=scan.id, asset_id=asset_id,
                        severity='High' if is_telnet else 'Medium', cve='',
                        description=f"Remote administration service ({service_name}) detected on port {port_id}/{proto}.",
                        recommendation=(
                            "Telnet transmits credentials in cleartext; replace with SSH."
                            if is_telnet else
                            "Confirm business justification and restrict source IPs; disable if unused."
                        ),
                        source_tool='nmap', is_auto_fail=is_telnet
                    ))

                # NSE script output: vuln.* scripts and DNS zone transfer
                for script in port_el.findall('script'):
                    script_id = script.get('id', '')
                    output = script.get('output', '')
                    is_zone_transfer = script_id == 'dns-zone-transfer' and 'NSEC' not in output and len(output.strip()) > 0
                    is_vuln_hit = 'VULNERABLE' in output

                    if is_zone_transfer or is_vuln_hit:
                        db.session.add(Finding(
                            scan_id=scan.id, asset_id=asset_id, severity='High', cve='',
                            description=f"Nmap NSE [{script_id}] on port {port_id}/{proto}: {output[:500]}",
                            recommendation="Review and remediate per NSE script guidance.",
                            source_tool='nmap',
                            # PCI §6/§7: unrestricted DNS zone transfer is an explicit auto-fail
                            is_auto_fail=is_zone_transfer
                        ))

            if os_name:
                db.session.add(Finding(
                    scan_id=scan.id, asset_id=asset_id, severity='Informational', cve='',
                    description=f"OS fingerprint: {os_name}", recommendation='',
                    source_tool='nmap', is_auto_fail=False
                ))

        db.session.commit()
    except subprocess.TimeoutExpired:
        print(f"Nmap scan timed out for {target}")
        raise
    except Exception as e:
        print(f"Nmap error: {e}")
        raise
    finally:
        try:
            os.remove(xml_path)
        except OSError:
            pass

    return open_ports


def _run_testssl_scan(scan_id, asset_id, target, open_ports, db, Finding):
    """PCI §6.2: SSL/early-TLS auto-fail, downgrade attacks, weak ciphers,
    certificate issues. Only runs against ports Nmap identified as TLS.
    """
    from models import Scan
    scan = Scan.query.get(scan_id)

    tls_ports = [p['port'] for p in open_ports if p['port'] in TLS_PORTS or p['service'] in ('https', 'ssl')]
    if not tls_ports:
        return

    scan.progress = f"Running testssl.sh on {target}..."
    scan.progress_percent = 30
    db.session.commit()

    # PCI DSS explicit automatic-fail protocols (§6.2, §7): SSLv2/v3, TLS 1.0/1.1.
    AUTO_FAIL_PROTOCOL_IDS = {'SSLv2', 'SSLv3', 'TLS1', 'TLS1_1'}

    for port in tls_ports:
        tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False)
        json_path = tmp.name
        tmp.close()

        cmd = ['testssl.sh', '--quiet', '--jsonfile', json_path, f'{target}:{port}']
        try:
            subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=600)

            with open(json_path) as f:
                results = json.load(f)

            for entry in results:
                entry_id = entry.get('id', '')
                severity_raw = entry.get('severity', 'INFO').upper()
                finding_text = entry.get('finding', '')

                is_early_protocol_offered = (
                    entry_id in AUTO_FAIL_PROTOCOL_IDS
                    and 'not offered' not in finding_text.lower()
                    and 'offered' in finding_text.lower()
                )

                if severity_raw in ('CRITICAL', 'HIGH') or is_early_protocol_offered:
                    severity = 'Critical' if severity_raw == 'CRITICAL' else 'High'
                    db.session.add(Finding(
                        scan_id=scan.id, asset_id=asset_id, severity=severity, cve='',
                        description=f"testssl.sh [{entry_id}] on port {port}: {finding_text}",
                        recommendation="Disable SSL/early TLS; support TLS 1.2+ only with strong cipher suites.",
                        source_tool='testssl',
                        is_auto_fail=is_early_protocol_offered
                    ))

            db.session.commit()
        except subprocess.TimeoutExpired:
            print(f"testssl.sh timed out for {target}:{port}")
        except Exception as e:
            print(f"testssl.sh error for {target}:{port}: {e}")
        finally:
            try:
                os.remove(json_path)
            except OSError:
                pass


def _get_zap_base_url():
    """ZAP_HOST defaults to the docker-compose service name ('zap'); dev.sh
    overrides it to 'localhost' for the host-run worker, same pattern as
    GVM_HOST for OpenVAS.
    """
    zap_host = os.environ.get('ZAP_HOST', 'zap')
    zap_port = os.environ.get('ZAP_PORT', '8090')
    return f"http://{zap_host}:{zap_port}"


def _run_zap_scan(scan_id, asset_id, target, open_ports, db, Finding):
    """PCI §6.3 auto-fail: SQL injection, XSS, directory traversal, HTTP
    response splitting. Spider + active scan (passive-only misses these).
    A ZAP failure is logged and treated as non-fatal for the overall scan,
    since ZAP is a new dependency here and shouldn't take down the whole
    pipeline the way an OpenVAS/Nuclei failure does.
    """
    from models import Scan
    scan = Scan.query.get(scan_id)

    web_ports = [p for p in open_ports if p['port'] in WEB_PORTS or p['service'] in ('http', 'https')]
    if not web_ports:
        return

    port = web_ports[0]['port']
    scheme = 'https' if port in TLS_PORTS else 'http'
    target_url = f"{scheme}://{target}:{port}"

    base = _get_zap_base_url()
    scan.progress = f"Running OWASP ZAP against {target_url}..."
    scan.progress_percent = 45
    db.session.commit()

    try:
        # 1. Spider — discover URLs/forms to feed the active scan
        r = requests.get(f"{base}/JSON/spider/action/scan/", params={'url': target_url}, timeout=30)
        spider_id = r.json().get('scan')
        waited = 0
        while waited < 600:
            status = requests.get(f"{base}/JSON/spider/view/status/", params={'scanId': spider_id}, timeout=30).json()
            if int(status.get('status', 0)) >= 100:
                break
            time.sleep(5)
            waited += 5

        scan.progress = f"ZAP active scan against {target_url}..."
        db.session.commit()

        # 2. Active scan — required to actually trigger SQLi/XSS/traversal
        # checks; ZAP's passive scan alone will not surface these.
        r = requests.get(f"{base}/JSON/ascan/action/scan/", params={'url': target_url, 'recurse': 'true'}, timeout=30)
        ascan_id = r.json().get('scan')
        waited = 0
        while waited < 1800:
            status = requests.get(f"{base}/JSON/ascan/view/status/", params={'scanId': ascan_id}, timeout=30).json()
            pct = int(status.get('status', 0))
            if pct >= 100:
                break
            time.sleep(15)
            waited += 15
            scan.progress = f"ZAP active scan {pct}% complete..."
            db.session.commit()

        # 3. Pull alerts
        alerts = requests.get(f"{base}/JSON/core/view/alerts/", params={'baseurl': target_url}, timeout=30).json().get('alerts', [])

        AUTO_FAIL_KEYWORDS = ('sql injection', 'cross site scripting', 'path traversal', 'directory traversal', 'response splitting')

        for alert in alerts:
            name = alert.get('alert', '')
            risk = alert.get('risk', 'Informational')
            desc = alert.get('description', '')
            solution = alert.get('solution', '')

            is_auto_fail = any(k in name.lower() for k in AUTO_FAIL_KEYWORDS)
            severity = 'High' if is_auto_fail else risk

            db.session.add(Finding(
                scan_id=scan.id, asset_id=asset_id, severity=severity, cve='',
                description=f"ZAP: {name} — {desc[:400]}",
                recommendation=solution[:500],
                source_tool='zap', is_auto_fail=is_auto_fail
            ))

        db.session.commit()
    except Exception as e:
        # Non-fatal by design — see docstring.
        print(f"ZAP scan error for {target_url}: {e}")


def _get_gvm_connection():
    """Build a GVM connection appropriate to the current environment.

    - GVM_HOST set (./dev.sh: worker runs on host): TLS connection to
      gvmd's GMP TCP listener (port 9390 by default, matches
      docker-compose.dev.yml / README).
    - GVM_HOST unset (full docker-compose: worker runs in a container
      that shares the gvmd_socket volume with the openvas container):
      Unix socket connection.
    """
    from gvm.connections import TLSConnection, UnixSocketConnection
    gvm_host = os.environ.get('GVM_HOST')
    if gvm_host:
        gvm_port = int(os.environ.get('GVM_PORT', 9390))
        return TLSConnection(hostname=gvm_host, port=gvm_port)
    socket_path = os.environ.get('GVM_SOCKET_PATH', '/run/gvmd/gvmd.sock')
    return UnixSocketConnection(path=socket_path)


def _run_openvas_scan(scan_id, asset_id, target, db, Finding):
    from models import Scan
    from gvm.protocols.gmp import Gmp
    from gvm.transforms import EtreeTransform
    scan = Scan.query.get(scan_id)
    scan.progress = f"Connecting to OpenVAS for {target}..."
    db.session.commit()

    gvm_host = os.environ.get('GVM_HOST')
    socket_path = os.environ.get('GVM_SOCKET_PATH', '/run/gvmd/gvmd.sock')

    # Only the socket-based (in-docker) path has a local file to wait on;
    # the TCP/TLS path (dev host) just relies on the connect-retry loop below.
    if not gvm_host:
        max_wait = 900
        waited = 0
        while not os.path.exists(socket_path) and waited < max_wait:
            time.sleep(10)
            waited += 10
            scan.progress = f"Waiting for OpenVAS to initialize ({waited}/{max_wait}s)..."
            db.session.commit()

        if not os.path.exists(socket_path):
            raise Exception(f"OpenVAS socket not found at {socket_path} after {max_wait} seconds.")

    # We attempt to connect to OpenVAS
    try:
        from gvm.protocols.gmp.requests.v224 import AliveTest
        connection = _get_gvm_connection()

        # Wait until the connection is actually accepted
        connected = False
        connect_wait = 0
        while not connected and connect_wait < 900:
            try:
                connection.connect()
                connection.disconnect()
                connected = True
            except Exception as e:
                time.sleep(10)
                connect_wait += 10
                scan.progress = f"Waiting for OpenVAS connection ({connect_wait}/900s)..."
                db.session.commit()

        if not connected:
            raise Exception(f"Could not connect to OpenVAS socket after 900 seconds.")

        transform = EtreeTransform()

        with Gmp(connection=connection, transform=transform) as gmp:
            gmp.authenticate('admin', 'admin')
            # 1. Get Port List
            res = gmp.get_port_lists(filter_string="name=All IANA assigned TCP")
            port_lists = res.xpath('port_list/@id')
            if not port_lists:
                raise Exception("OpenVAS Error: Could not find port list 'All IANA assigned TCP'")
            port_list_id = port_lists[0]

            # 2. Get Config
            res = gmp.get_scan_configs(filter_string="name=Base")
            configs = res.xpath('config/@id')
            if not configs:
                raise Exception("OpenVAS Error: Could not find scan config 'Base'")
            config_id = configs[0]

            # 3. Get Scanner
            res = gmp.get_scanners(filter_string="name=CVE")
            scanners = res.xpath('scanner/@id')
            if not scanners:
                raise Exception("OpenVAS Error: Could not find scanner 'CVE'")
            scanner_id = scanners[0]

            scan.progress = f"Creating OpenVAS target {target}..."
            scan.progress_percent = 65
            db.session.commit()

            # Create target (Consider Alive to bypass ping failures)
            res = gmp.create_target(name=f"Target-{target}-{scan.id}", hosts=[target], port_list_id=port_list_id, alive_test=AliveTest.CONSIDER_ALIVE)
            if res.get('status') != '201':
                raise Exception(f"OpenVAS Error creating target: {res.get('status_text')}")

            target_id = res.xpath('//@id')[0]
            scan.progress = "Creating OpenVAS task..."
            scan.progress_percent = 68
            db.session.commit()

            # Create task
            res = gmp.create_task(name=f"Task-{target}-{scan.id}", config_id=config_id, target_id=target_id, scanner_id=scanner_id)
            if res.get('status') != '201':
                raise Exception(f"OpenVAS Error creating task: {res.get('status_text')}")

            task_id = res.xpath('//@id')[0]

            scan.openvas_task_id = task_id
            db.session.commit()

            # Start task
            res = gmp.start_task(task_id)
            if res.get('status') != '202':
                raise Exception(f"OpenVAS Error starting task: {res.get('status_text')}")

            report_id = res.xpath('//report_id')[0].text

            scan.progress = f"Polling OpenVAS task..."
            scan.progress_percent = 70
            db.session.commit()

            # Poll status
            while True:
                task = gmp.get_task(task_id)
                status = task.xpath('//status')[0].text

                # Fetch progress
                progress_node = task.xpath('//progress')
                if progress_node and progress_node[0].text and progress_node[0].text.isdigit():
                    val = int(progress_node[0].text)
                    if val > 0:
                        scan.progress_percent = min(95, max(70, 70 + int(val * 0.25)))
                        db.session.commit()

                if status in ['Done', 'Stopped']:
                    break
                elif status in ['Interrupted', 'Failed', 'Error']:
                    raise Exception(f"OpenVAS task failed with status: {status}")
                time.sleep(10)

            # Fetch results
            scan.progress = f"Parsing OpenVAS results..."
            scan.progress_percent = 98
            db.session.commit()

            results = gmp.get_results(filter_string=f"report_id={report_id}")
            for result in results.xpath('//result'):
                severity_node = result.find('threat')
                severity = severity_node.text if severity_node is not None else 'Informational'
                if severity == 'Log': severity = 'Informational'

                desc_node = result.find('description')
                desc = desc_node.text if desc_node is not None else ''

                cve = ''
                nvt = result.find('nvt')
                if nvt is not None:
                    cve_node = nvt.find('cve')
                    if cve_node is not None and cve_node.text != 'NOCVE':
                        cve = cve_node.text

                # PCI 1.4.4 / §6.6 note: databases exposed to the Internet are
                # already flagged (auto-fail) by _run_nmap_scan via port; this
                # OpenVAS pass is CVE-based, not overlapping that rule.
                db.session.add(Finding(
                    scan_id=scan.id,
                    asset_id=asset_id,
                    severity=severity,
                    cve=cve,
                    description=desc.strip(),
                    recommendation='',
                    source_tool='openvas',
                    is_auto_fail=False
                ))

            db.session.commit()
    except Exception as e:
        print(f"OpenVAS integration error: {e}")
        raise e
