"""RBAC role gating and multi-tenant isolation, including direct IDOR
probes against another organization's data by ID -- not just checking
that list views are filtered."""
from tests.conftest import get_csrf_token


def _second_org(client, bootstrap):
    """Onboards a second organization ('Globex') as ASV staff, returns
    its admin credentials. Leaves the client logged out afterward."""
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    token = get_csrf_token(client, '/admin/organizations')
    client.post('/admin/organizations', data={
        'name': 'Globex Corp', 'admin_email': 'admin@globex.example', 'admin_password': 'GlobexAdminPass123!',
        'csrf_token': token,
    })
    client.get('/logout')
    return {'email': 'admin@globex.example', 'password': 'GlobexAdminPass123!'}


def test_findings_list_page_renders_with_no_findings(as_admin):
    """Regression test: /findings previously 500'd unconditionally --
    templates/findings.html (the LIST page) had been overwritten with
    finding_detail.html's content (the SINGLE-finding detail page),
    which references a `finding` variable this route's context never
    provides (only the plural `findings`). Caught by this test suite."""
    r = as_admin.get('/findings')
    assert r.status_code == 200


def test_findings_list_page_renders_with_real_data(as_admin, bootstrap):
    from models import Organization, Asset, Scan, Finding
    from app import db
    from tasks import _make_finding
    from unittest.mock import patch

    with as_admin.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=org.id, hostname='web.example.com', ip_address='1.2.3.4')
        db.session.add(asset); db.session.commit()
        scan = Scan(organization_id=org.id, type='external', status='completed')
        db.session.add(scan); db.session.commit()
        with patch('cvss_engine.fetch_nvd_cvss', return_value=(9.0, 'NVD-CVSSv3.1')):
            f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Critical',
                               cve='CVE-2024-99', description='test finding', recommendation='fix it',
                               source_tool='zap', is_auto_fail=True)
            db.session.add(f); db.session.commit()

    r = as_admin.get('/findings')
    assert r.status_code == 200
    assert b'CVE-2024-99' in r.data
    assert b'web.example.com' in r.data


def test_executive_role_is_read_only_for_asset_creation(client, bootstrap):
    from models import User, Organization
    from app import db

    with client.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        exec_user = User(organization_id=org.id, email='exec@acme.example', role='executive')
        exec_user.set_password('ExecPass123!')
        db.session.add(exec_user); db.session.commit()

    token = get_csrf_token(client, '/login')
    client.post('/login', data={'email': 'exec@acme.example', 'password': 'ExecPass123!', 'csrf_token': token})

    # /assets/new itself requires admin/analyst even for GET, so an
    # executive session can't reach it to pull a token -- CSRF tokens
    # are session-scoped, not page-scoped, so any page the executive CAN
    # reach works just as well.
    token = get_csrf_token(client, '/reports')
    r = client.post('/assets/new', data={
        'hostname': 'sneaky.example.com', 'ip_address': '10.0.0.1', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'do not have permission' in r.data

    from models import Asset
    with client.application.app_context():
        assert Asset.query.filter_by(hostname='sneaky.example.com').first() is None


def test_executive_role_can_still_view_findings(client, bootstrap):
    from models import User, Organization
    from app import db

    with client.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        exec_user = User(organization_id=org.id, email='exec2@acme.example', role='executive')
        exec_user.set_password('ExecPass123!')
        db.session.add(exec_user); db.session.commit()

    token = get_csrf_token(client, '/login')
    client.post('/login', data={'email': 'exec2@acme.example', 'password': 'ExecPass123!', 'csrf_token': token})
    r = client.get('/findings')
    assert r.status_code == 200


def test_customer_admin_cannot_reach_dispute_review_queue(as_admin):
    r = as_admin.get('/disputes', follow_redirects=True)
    assert b'do not have permission' in r.data


def test_customer_admin_cannot_self_approve_a_dispute(as_admin, bootstrap):
    """The exact gap flagged in the original audit: dispute approval had
    no access control at all."""
    from models import Organization, Asset, Scan, Finding, Dispute
    from app import db
    from unittest.mock import patch
    from tasks import _make_finding

    with as_admin.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=org.id, ip_address='10.0.0.5'); db.session.add(asset); db.session.commit()
        scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()
        with patch('cvss_engine.fetch_nvd_cvss', return_value=(9.0, 'NVD-CVSSv3.1')):
            f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Critical',
                               cve='CVE-1', description='x', recommendation='y', source_tool='zap', is_auto_fail=True)
            db.session.add(f); db.session.commit()
        finding_id = f.id

    token = get_csrf_token(as_admin, f'/findings/{finding_id}')
    as_admin.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'false_positive', 'evidence_text': 'not real', 'csrf_token': token,
    })
    with as_admin.application.app_context():
        dispute = Dispute.query.filter_by(finding_id=finding_id).first()
        dispute_id = dispute.id

    token = get_csrf_token(as_admin, f'/findings/{finding_id}')
    r = as_admin.post(f'/disputes/{dispute_id}/decision', data={
        'decision': 'approved', 'decision_notes': 'self-approve attempt', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'do not have permission' in r.data

    with as_admin.application.app_context():
        assert Dispute.query.get(dispute_id).decision == 'pending'


def test_asv_staff_can_reach_dispute_queue(as_asv_staff):
    r = as_asv_staff.get('/disputes')
    assert r.status_code == 200


def test_customer_admin_cannot_generate_official_pci_report(as_admin, bootstrap):
    from models import Scan, Organization
    from app import db

    with as_admin.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        scan = Scan(organization_id=org.id, type='external', status='completed')
        db.session.add(scan); db.session.commit()
        scan_id = scan.id

    token = get_csrf_token(as_admin, '/reports')
    r = as_admin.post('/reports/generate/full', data={'scan_id': str(scan_id), 'csrf_token': token}, follow_redirects=True)
    assert b'do not have permission' in r.data


def test_second_org_admin_cannot_see_first_orgs_assets_in_list(client, bootstrap):
    globex_admin = _second_org(client, bootstrap)

    from models import Organization, Asset
    from app import db
    with client.application.app_context():
        acme = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=acme.id, hostname='acme-secret.example.com', ip_address='10.0.0.9')
        db.session.add(asset); db.session.commit()

    token = get_csrf_token(client, '/login')
    client.post('/login', data={'email': globex_admin['email'], 'password': globex_admin['password'], 'csrf_token': token})
    r = client.get('/assets')
    assert b'acme-secret.example.com' not in r.data


def test_second_org_admin_cannot_view_first_orgs_asset_by_direct_id_idor(client, bootstrap):
    """The IDOR probe: not just 'is it hidden from the list,' but 'is it
    actually blocked when requested directly by ID.'"""
    globex_admin = _second_org(client, bootstrap)

    from models import Organization, Asset
    from app import db
    with client.application.app_context():
        acme = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=acme.id, hostname='acme-idor-target.example.com', ip_address='10.0.0.10')
        db.session.add(asset); db.session.commit()
        asset_id = asset.id

    token = get_csrf_token(client, '/login')
    client.post('/login', data={'email': globex_admin['email'], 'password': globex_admin['password'], 'csrf_token': token})
    r = client.get(f'/assets/{asset_id}', follow_redirects=True)
    assert b'do not have access' in r.data


def test_scan_creation_rejects_tampered_asset_id_from_another_org(client, bootstrap):
    """A form field can be edited client-side -- the server must
    independently verify every asset_id belongs to the submitter's org."""
    globex_admin = _second_org(client, bootstrap)

    from models import Organization, Asset
    from app import db
    with client.application.app_context():
        acme = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=acme.id, hostname='acme-scan-target.example.com', ip_address='10.0.0.11')
        db.session.add(asset); db.session.commit()
        asset_id = asset.id

    token = get_csrf_token(client, '/login')
    client.post('/login', data={'email': globex_admin['email'], 'password': globex_admin['password'], 'csrf_token': token})

    token = get_csrf_token(client, '/scans/new')
    r = client.post('/scans/new', data={
        'type': 'external', 'asset_ids': [str(asset_id)], 'csrf_token': token,
    }, follow_redirects=True)
    assert b'not in your organization' in r.data

    from models import Scan
    with client.application.app_context():
        globex = Organization.query.filter_by(name='Globex Corp').first()
        assert Scan.query.filter_by(organization_id=globex.id).count() == 0
