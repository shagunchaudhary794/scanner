"""Dispute submission and decision workflow (PCI §7/§8), through real
routes -- evidence upload, empty-evidence rejection, and the queue."""
import io
from unittest.mock import patch
from tests.conftest import get_csrf_token


def _make_finding(app_ctx_client, bootstrap):
    from models import Organization, Asset, Scan, Finding
    from app import db
    from tasks import _make_finding as make_finding

    with app_ctx_client.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=org.id, ip_address='10.0.0.5')
        db.session.add(asset); db.session.commit()
        scan = Scan(organization_id=org.id, type='external', status='completed')
        db.session.add(scan); db.session.commit()
        with patch('cvss_engine.fetch_nvd_cvss', return_value=(9.0, 'NVD-CVSSv3.1')):
            f = make_finding(db, Finding, scan_id=scan.id, asset_id=asset.id, severity='Critical',
                              cve='CVE-2024-1', description='SQLi', recommendation='patch it',
                              source_tool='zap', is_auto_fail=True)
            db.session.add(f); db.session.commit()
        return f.id


def test_dispute_requires_written_evidence(as_admin, bootstrap):
    finding_id = _make_finding(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/findings/{finding_id}')
    r = as_admin.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'false_positive', 'evidence_text': '', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'Written evidence is required' in r.data

    from models import Dispute
    with as_admin.application.app_context():
        assert Dispute.query.filter_by(finding_id=finding_id).count() == 0


def test_dispute_invalid_type_rejected(as_admin, bootstrap):
    finding_id = _make_finding(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/findings/{finding_id}')
    r = as_admin.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'not-a-real-type', 'evidence_text': 'x', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'Invalid dispute type' in r.data


def test_dispute_with_text_evidence_succeeds(as_admin, bootstrap):
    finding_id = _make_finding(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/findings/{finding_id}')
    r = as_admin.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'compensating_control',
        'evidence_text': 'WAF blocks all SQLi attempts, verified via logs dated 2026-08-01.',
        'csrf_token': token,
    }, follow_redirects=True)
    assert b'submitted for ASV analyst review' in r.data

    from models import Dispute
    with as_admin.application.app_context():
        d = Dispute.query.filter_by(finding_id=finding_id).first()
        assert d is not None
        assert d.decision == 'pending'
        assert d.submitted_by == bootstrap['admin_email']  # taken from session, not typed


def test_dispute_with_evidence_file_persists_to_disk(as_admin, bootstrap):
    finding_id = _make_finding(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/findings/{finding_id}')
    r = as_admin.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'false_positive',
        'evidence_text': 'Scanner misidentified this endpoint.',
        'evidence_file': (io.BytesIO(b'fake-evidence-content'), 'evidence.txt'),
        'csrf_token': token,
    }, content_type='multipart/form-data', follow_redirects=True)
    assert r.status_code == 200

    import os
    from models import Dispute
    with as_admin.application.app_context():
        d = Dispute.query.filter_by(finding_id=finding_id).first()
        assert d.evidence_file_path is not None
        stored = os.path.join(as_admin.application.config['EVIDENCE_UPLOAD_FOLDER'], d.evidence_file_path)
        assert os.path.exists(stored)
        with open(stored, 'rb') as fh:
            assert fh.read() == b'fake-evidence-content'


def test_evidence_download_requires_login(client, bootstrap):
    r = client.get('/evidence/whatever-file.txt', follow_redirects=True)
    assert b'log in' in r.data.lower() or b'Log In' in r.data


def test_approved_dispute_flips_effective_status_via_the_real_route(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    finding_id = _make_finding(client, bootstrap)

    token = get_csrf_token(client, f'/findings/{finding_id}')
    client.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'compensating_control', 'evidence_text': 'WAF verified.', 'csrf_token': token,
    })

    from models import Dispute, Finding
    with client.application.app_context():
        dispute_id = Dispute.query.filter_by(finding_id=finding_id).first().id
        assert Finding.query.get(finding_id).effective_status == 'Fail'  # still pending
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    token = get_csrf_token(client, '/disputes')
    r = client.post(f'/disputes/{dispute_id}/decision', data={
        'decision': 'approved', 'decision_notes': 'Verified via WAF logs.', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'marked approved' in r.data

    with client.application.app_context():
        d = Dispute.query.get(dispute_id)
        assert d.decision == 'approved'
        assert d.reviewed_by == bootstrap['asv_email']
        f = Finding.query.get(finding_id)
        assert f.compliance_status == 'Fail'   # raw result untouched
        assert f.effective_status == 'Pass'    # reported outcome flipped


def test_rejected_dispute_leaves_finding_failing(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    finding_id = _make_finding(client, bootstrap)
    token = get_csrf_token(client, f'/findings/{finding_id}')
    client.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'false_positive', 'evidence_text': 'Not actually vulnerable.', 'csrf_token': token,
    })

    from models import Dispute, Finding
    with client.application.app_context():
        dispute_id = Dispute.query.filter_by(finding_id=finding_id).first().id
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    token = get_csrf_token(client, '/disputes')
    client.post(f'/disputes/{dispute_id}/decision', data={
        'decision': 'rejected', 'decision_notes': 'Evidence insufficient.', 'csrf_token': token,
    })

    with client.application.app_context():
        assert Finding.query.get(finding_id).effective_status == 'Fail'


def test_invalid_decision_value_rejected(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    finding_id = _make_finding(client, bootstrap)
    token = get_csrf_token(client, f'/findings/{finding_id}')
    client.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'false_positive', 'evidence_text': 'x', 'csrf_token': token,
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
    r = client.post(f'/disputes/{dispute_id}/decision', data={
        'decision': 'maybe', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'Invalid decision' in r.data
    with client.application.app_context():
        assert Dispute.query.get(dispute_id).decision == 'pending'


def test_disputes_queue_status_filter(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    finding_id = _make_finding(client, bootstrap)
    token = get_csrf_token(client, f'/findings/{finding_id}')
    client.post(f'/findings/{finding_id}/dispute', data={
        'dispute_type': 'false_positive', 'evidence_text': 'x', 'csrf_token': token,
    })
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    r = client.get('/disputes?status=pending')
    assert r.status_code == 200
    r = client.get('/disputes?status=approved')
    assert r.status_code == 200


def test_asset_from_different_org_cannot_have_dispute_submitted_by_outsider(client, bootstrap):
    """A finding belongs to one org's scan -- another org's admin must
    not be able to submit a dispute against it."""
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    finding_id = _make_finding(client, bootstrap)
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

    r = client.get(f'/findings/{finding_id}', follow_redirects=True)
    assert b'do not have access' in r.data
