"""Model-level business logic: Finding's dual compliance status, User
login lockout, Report expiry."""
from datetime import datetime, timedelta
from unittest.mock import patch


def test_finding_compliance_status_fail_on_high_cvss(app, db):
    from models import Organization, Asset, Scan, Finding
    from tasks import _make_finding

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, ip_address='10.0.0.1'); db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()

    with patch('cvss_engine.fetch_nvd_cvss', return_value=(6.5, 'NVD-CVSSv3.1')):
        f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Medium',
                           cve='CVE-2024-1', description='x', recommendation='y',
                           source_tool='nmap', is_auto_fail=False)
        db.session.add(f); db.session.commit()

    assert f.compliance_status == 'Fail'  # 6.5 >= 4.0


def test_finding_compliance_status_pass_below_threshold(app, db):
    from models import Organization, Asset, Scan, Finding
    from tasks import _make_finding

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, ip_address='10.0.0.1'); db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()

    with patch('cvss_engine.fetch_nvd_cvss', return_value=(2.1, 'NVD-CVSSv3.1')):
        f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Low',
                           cve='CVE-2024-2', description='x', recommendation='y',
                           source_tool='nmap', is_auto_fail=False)
        db.session.add(f); db.session.commit()

    assert f.compliance_status == 'Pass'


def test_auto_fail_is_fail_even_with_no_cvss_score(app, db):
    from models import Organization, Asset, Scan, Finding
    from tasks import _make_finding

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, ip_address='10.0.0.1'); db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()

    with patch('cvss_engine.fetch_nvd_cvss', return_value=None):
        f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Informational',
                           cve='', description='default creds', recommendation='change it',
                           source_tool='default-creds-check', is_auto_fail=True)
        db.session.add(f); db.session.commit()

    assert f.compliance_status == 'Fail'


def test_effective_status_matches_raw_status_with_no_dispute(app, db):
    from models import Organization, Asset, Scan, Finding
    from tasks import _make_finding

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, ip_address='10.0.0.1'); db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()

    with patch('cvss_engine.fetch_nvd_cvss', return_value=(9.0, 'NVD-CVSSv3.1')):
        f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Critical',
                           cve='CVE-2024-3', description='x', recommendation='y',
                           source_tool='zap', is_auto_fail=False)
        db.session.add(f); db.session.commit()

    assert f.effective_status == f.compliance_status == 'Fail'
    assert f.approved_dispute is None
    assert f.exception_note == ''


def test_effective_status_flips_on_approved_dispute_but_raw_status_does_not(app, db):
    """The core dispute-workflow correctness property (§7/§8): a finding
    is never edited by a dispute, only its REPORTED outcome changes."""
    from models import Organization, Asset, Scan, Finding, Dispute
    from tasks import _make_finding

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, ip_address='10.0.0.1'); db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()

    with patch('cvss_engine.fetch_nvd_cvss', return_value=(7.5, 'NVD-CVSSv3.1')):
        f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='High',
                           cve='CVE-2024-4', description='x', recommendation='y',
                           source_tool='testssl', is_auto_fail=False)
        db.session.add(f); db.session.commit()

    dispute = Dispute(finding_id=f.id, dispute_type='compensating_control',
                       evidence_text='WAF blocks this', decision='approved',
                       decision_notes='Verified by analyst')
    db.session.add(dispute); db.session.commit()

    assert f.compliance_status == 'Fail'   # raw technical result: unchanged
    assert f.effective_status == 'Pass'    # reported outcome: flipped
    assert f.approved_dispute is not None
    assert 'Compensating Control' in f.exception_note


def test_pending_dispute_does_not_flip_effective_status(app, db):
    from models import Organization, Asset, Scan, Finding, Dispute
    from tasks import _make_finding

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, ip_address='10.0.0.1'); db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()

    with patch('cvss_engine.fetch_nvd_cvss', return_value=(7.5, 'NVD-CVSSv3.1')):
        f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='High',
                           cve='CVE-2024-5', description='x', recommendation='y',
                           source_tool='testssl', is_auto_fail=False)
        db.session.add(f); db.session.commit()

    dispute = Dispute(finding_id=f.id, dispute_type='false_positive',
                       evidence_text='not real', decision='pending')
    db.session.add(dispute); db.session.commit()

    assert f.effective_status == 'Fail'  # still pending -- no change yet


def test_rejected_dispute_does_not_flip_effective_status(app, db):
    from models import Organization, Asset, Scan, Finding, Dispute
    from tasks import _make_finding

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, ip_address='10.0.0.1'); db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type='external', status='completed'); db.session.add(scan); db.session.commit()

    with patch('cvss_engine.fetch_nvd_cvss', return_value=(7.5, 'NVD-CVSSv3.1')):
        f = _make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='High',
                           cve='CVE-2024-6', description='x', recommendation='y',
                           source_tool='testssl', is_auto_fail=False)
        db.session.add(f); db.session.commit()

    dispute = Dispute(finding_id=f.id, dispute_type='false_positive',
                       evidence_text='not real', decision='rejected')
    db.session.add(dispute); db.session.commit()

    assert f.effective_status == 'Fail'


def test_user_lockout_threshold_and_reset(app, db):
    from models import User, Organization

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    user = User(organization_id=org.id, email='u@example.com', role='admin')
    user.set_password('correct-password')
    db.session.add(user); db.session.commit()

    for i in range(1, 5):
        user.register_failed_login()
        assert user.is_locked_out is False, f"locked too early at attempt {i}"

    user.register_failed_login()  # 5th
    assert user.is_locked_out is True
    assert user.failed_login_attempts == 5

    user.locked_until = datetime.utcnow() - timedelta(seconds=1)  # simulate expiry
    assert user.is_locked_out is False

    user.register_successful_login()
    assert user.failed_login_attempts == 0
    assert user.locked_until is None


def test_user_lockout_handles_none_attempts_gracefully(app, db):
    """Regression test: existing rows migrated from before this field
    existed could have NULL failed_login_attempts; += would crash."""
    from models import User, Organization

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    user = User(organization_id=org.id, email='u2@example.com', role='admin')
    user.set_password('x')
    user.failed_login_attempts = None
    db.session.add(user); db.session.commit()

    user.register_failed_login()  # must not raise
    assert user.failed_login_attempts == 1


def test_report_expiry_property(app, db):
    from models import Organization, Report

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()

    expired = Report(organization_id=org.id, type='t', format='csv', status='completed',
                      expires_at=datetime.utcnow() - timedelta(days=1))
    fresh = Report(organization_id=org.id, type='t', format='csv', status='completed',
                    expires_at=datetime.utcnow() + timedelta(days=89))
    db.session.add_all([expired, fresh]); db.session.commit()

    assert expired.is_expired is True
    assert fresh.is_expired is False


def test_asset_can_access_organization(app, db):
    from models import User, Organization

    org1 = Organization(name='Org1'); org2 = Organization(name='Org2')
    db.session.add_all([org1, org2]); db.session.commit()

    admin1 = User(organization_id=org1.id, email='a1@x.com', role='admin')
    admin1.set_password('x')
    asv = User(organization_id=None, email='asv@x.com', role='asv_staff')
    asv.set_password('x')
    db.session.add_all([admin1, asv]); db.session.commit()

    assert admin1.can_access_organization(org1.id) is True
    assert admin1.can_access_organization(org2.id) is False
    assert asv.can_access_organization(org1.id) is True   # ASV staff sees everyone
    assert asv.can_access_organization(org2.id) is True
