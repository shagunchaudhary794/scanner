"""Report generation, persistence, and the historical-fidelity property
(§10/§44) -- a stored report must never silently change after the fact."""
import os
from unittest.mock import patch
from tests.conftest import get_csrf_token


def _scan_with_finding(client, bootstrap):
    from models import Organization, Asset, Scan, ScanTarget, Finding
    from app import db
    from tasks import _make_finding

    with client.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=org.id, hostname='web01.example.com', ip_address='10.0.0.5')
        db.session.add(asset); db.session.commit()
        scan = Scan(organization_id=org.id, type='external', status='completed')
        db.session.add(scan); db.session.commit()
        db.session.add(ScanTarget(scan_id=scan.id, asset_id=asset.id)); db.session.commit()
        with patch('cvss_engine.fetch_nvd_cvss', return_value=(9.0, 'NVD-CVSSv3.1')):
            f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Critical',
                               cve='CVE-2024-1', description='SQLi on port 443/tcp', recommendation='patch it',
                               source_tool='zap', is_auto_fail=True)
            db.session.add(f); db.session.commit()
        return scan.id, f.id


def test_csv_report_persists_to_disk_and_matches_download(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    scan_id, _ = _scan_with_finding(client, bootstrap)

    token = get_csrf_token(client, '/reports')
    r = client.post('/reports/generate', data={'scan_id': str(scan_id), 'format': 'csv', 'csrf_token': token})
    assert r.status_code == 200
    original = r.data

    from models import Report
    with client.application.app_context():
        report = Report.query.filter_by(format='csv').order_by(Report.id.desc()).first()
        assert report.file_path is not None
        stored = os.path.join(client.application.config['REPORTS_STORAGE_FOLDER'], report.file_path)
        assert os.path.exists(stored)
        with open(stored, 'rb') as fh:
            assert fh.read() == original
        report_id = report.id

    r2 = client.get(f'/reports/{report_id}/download')
    assert r2.data == original
    assert r2.headers['Content-Type'] == 'text/csv'


def test_pdf_report_persists_and_matches_download(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    scan_id, _ = _scan_with_finding(client, bootstrap)

    token = get_csrf_token(client, '/reports')
    r = client.post('/reports/generate', data={'scan_id': str(scan_id), 'format': 'pdf', 'csrf_token': token})
    assert r.status_code == 200
    original = r.data
    assert len(original) > 500  # a real PDF, not an error page

    from models import Report
    with client.application.app_context():
        report = Report.query.filter_by(format='pdf').order_by(Report.id.desc()).first()
        report_id = report.id

    r2 = client.get(f'/reports/{report_id}/download')
    assert r2.data == original
    assert r2.headers['Content-Type'] == 'application/pdf'


def test_report_expiry_and_retention_set_exactly(client, bootstrap):
    from datetime import timedelta
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    scan_id, _ = _scan_with_finding(client, bootstrap)

    token = get_csrf_token(client, '/reports')
    client.post('/reports/generate', data={'scan_id': str(scan_id), 'format': 'csv', 'csrf_token': token})

    from models import Report
    with client.application.app_context():
        report = Report.query.order_by(Report.id.desc()).first()
        assert (report.expires_at - report.created_at) == timedelta(days=90)
        assert (report.retention_until - report.created_at) == timedelta(days=365 * 3)


def test_historical_fidelity_original_report_unchanged_after_dispute_approval(client, bootstrap):
    """The core value proposition of report persistence: a report is a
    historical record of what was actually issued, not a live view."""
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    scan_id, finding_id = _scan_with_finding(client, bootstrap)

    token = get_csrf_token(client, '/reports')
    r = client.post('/reports/generate', data={'scan_id': str(scan_id), 'format': 'csv', 'csrf_token': token})
    original_content = r.data.decode()
    assert 'Fail' in original_content

    from models import Report
    with client.application.app_context():
        report_id = Report.query.filter_by(format='csv').order_by(Report.id.desc()).first().id

    # Dispute the finding and get it approved.
    token = get_csrf_token(client, f'/findings/{finding_id}')
    client.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'compensating_control', 'evidence_text': 'WAF verified.', 'csrf_token': token,
    })
    from models import Dispute
    with client.application.app_context():
        dispute_id = Dispute.query.filter_by(finding_id=finding_id).first().id
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    token = get_csrf_token(client, '/disputes')
    client.post(f'/disputes/{dispute_id}/decision', data={
        'decision': 'approved', 'decision_notes': 'Verified.', 'csrf_token': token,
    })
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })

    # Live status is now Pass...
    from models import Finding
    with client.application.app_context():
        assert Finding.query.get(finding_id).effective_status == 'Pass'

    # ...but re-downloading the ORIGINAL report must still say Fail.
    r2 = client.get(f'/reports/{report_id}/download')
    assert r2.data.decode() == original_content
    assert 'Fail' in r2.data.decode()

    # A freshly generated report now correctly shows Pass -- proves the
    # distinction is real, not an artifact of a broken CSV writer.
    token = get_csrf_token(client, '/reports')
    r3 = client.post('/reports/generate', data={'scan_id': str(scan_id), 'format': 'csv', 'csrf_token': token})
    fresh_lines = [l for l in r3.data.decode().split('\r\n') if 'CVE-2024-1' in l]
    assert fresh_lines and 'Fail' not in fresh_lines[0]


def test_cross_tenant_download_denied(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    scan_id, _ = _scan_with_finding(client, bootstrap)
    token = get_csrf_token(client, '/reports')
    client.post('/reports/generate', data={'scan_id': str(scan_id), 'format': 'csv', 'csrf_token': token})

    from models import Report
    with client.application.app_context():
        report_id = Report.query.order_by(Report.id.desc()).first().id
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    token = get_csrf_token(client, '/admin/organizations')
    client.post('/admin/organizations', data={
        'name': 'Globex Corp', 'admin_email': 'admin@globex.example', 'admin_password': 'GlobexPass123!',
        'csrf_token': token,
    })
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={'email': 'admin@globex.example', 'password': 'GlobexPass123!', 'csrf_token': token})
    r = client.get(f'/reports/{report_id}/download', follow_redirects=True)
    assert b'do not have access' in r.data


def test_report_with_no_stored_file_fails_gracefully(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    from models import Report, Organization
    from app import db
    with client.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        ghost = Report(organization_id=org.id, type='Legacy', format='csv', status='completed', file_path=None)
        db.session.add(ghost); db.session.commit()
        ghost_id = ghost.id

    r = client.get(f'/reports/{ghost_id}/download', follow_redirects=True)
    assert b'no longer available' in r.data


def test_pdf_generation_failure_marks_report_failed_not_orphaned(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    scan_id, _ = _scan_with_finding(client, bootstrap)

    token = get_csrf_token(client, '/reports')
    with patch('pdfkit.from_string', side_effect=Exception("wkhtmltopdf not found")):
        r = client.post('/reports/generate', data={'scan_id': str(scan_id), 'format': 'pdf', 'csrf_token': token}, follow_redirects=True)
        assert b'PDF generation failed' in r.data

    from models import Report
    with client.application.app_context():
        failed = Report.query.filter_by(status='failed').first()
        assert failed is not None
        assert failed.file_path is None


def test_full_pci_report_overall_result_and_excluded_asset_count(client, bootstrap):
    from models import Organization, Asset, Scan, ScanTarget, Finding
    from app import db
    from tasks import _make_finding

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })

    with client.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        in_scope = Asset(organization_id=org.id, hostname='in-scope.example.com', ip_address='10.0.0.1')
        excluded = Asset(organization_id=org.id, hostname='excluded.example.com', ip_address='10.0.0.2',
                          is_out_of_scope=True, segmentation_attestation='Isolated VLAN')
        db.session.add_all([in_scope, excluded]); db.session.commit()
        scan = Scan(organization_id=org.id, type='external', status='completed')
        db.session.add(scan); db.session.commit()
        db.session.add_all([
            ScanTarget(scan_id=scan.id, asset_id=in_scope.id),
            ScanTarget(scan_id=scan.id, asset_id=excluded.id),
        ]); db.session.commit()
        with patch('cvss_engine.fetch_nvd_cvss', return_value=(9.0, 'NVD-CVSSv3.1')):
            f = _make_finding(db, Finding, scan_id=scan.id, asset_id=in_scope.id, severity='Critical',
                               cve='CVE-2024-9', description='x', recommendation='y',
                               source_tool='zap', is_auto_fail=True)
            db.session.add(f); db.session.commit()
        scan_id = scan.id
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    token = get_csrf_token(client, '/reports')
    r = client.post('/reports/generate/full', data={'scan_id': str(scan_id), 'csrf_token': token})
    assert r.status_code == 200
    assert r.headers['Content-Type'] == 'application/pdf'

    from models import Report
    with client.application.app_context():
        report = Report.query.filter_by(report_type='full_pci').order_by(Report.id.desc()).first()
        assert report.overall_result == 'Fail'
        assert report.scan_id == scan_id
        assert report.status == 'completed'
