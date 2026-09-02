"""Asset scope management: segmentation attestation (§4.2), discovery
confirmation flow (§4.4), and multi-tenant hosting evidence (§5.7/§14)."""
import io
from tests.conftest import get_csrf_token


def _make_asset(client, bootstrap, hostname='scope-target.example.com'):
    from models import Organization, Asset
    from app import db
    with client.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=org.id, hostname=hostname, ip_address='10.0.0.20')
        db.session.add(asset); db.session.commit()
        return asset.id


# --- Segmentation attestation (§4.2) ---------------------------------------

def test_excluding_asset_without_attestation_is_rejected(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/scope', data={
        'action': 'exclude', 'segmentation_attestation': '', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'segmentation attestation is required' in r.data

    from models import Asset
    with as_admin.application.app_context():
        assert Asset.query.get(asset_id).is_out_of_scope is False


def test_excluding_asset_with_attestation_succeeds(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/scope', data={
        'action': 'exclude',
        'segmentation_attestation': 'Isolated on internal VLAN 40, no route to CDE per firewall ACL review.',
        'csrf_token': token,
    }, follow_redirects=True)
    assert b'Scope updated' in r.data

    from models import Asset
    with as_admin.application.app_context():
        asset = Asset.query.get(asset_id)
        assert asset.is_out_of_scope is True
        assert 'VLAN 40' in asset.segmentation_attestation


def test_reincluding_asset_preserves_attestation_history(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    as_admin.post(f'/assets/{asset_id}/scope', data={
        'action': 'exclude', 'segmentation_attestation': 'VLAN isolated.', 'csrf_token': token,
    })

    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    as_admin.post(f'/assets/{asset_id}/scope', data={'action': 'include', 'csrf_token': token})

    from models import Asset
    with as_admin.application.app_context():
        asset = Asset.query.get(asset_id)
        assert asset.is_out_of_scope is False
        assert asset.segmentation_attestation is not None  # history preserved, not wiped


def test_scope_change_on_another_orgs_asset_denied(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    asset_id = _make_asset(client, bootstrap)
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
    token = get_csrf_token(client, '/reports')
    r = client.post(f'/assets/{asset_id}/scope', data={
        'action': 'exclude', 'segmentation_attestation': 'trying to exclude someone elses asset', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'do not have access' in r.data

    from models import Asset
    with client.application.app_context():
        assert Asset.query.get(asset_id).is_out_of_scope is False


# --- Discovery route -------------------------------------------------------

def test_discovery_requires_a_hostname(as_admin, bootstrap):
    from models import Organization, Asset
    from app import db
    with as_admin.application.app_context():
        org = Organization.query.filter_by(name=bootstrap['org_name']).first()
        asset = Asset(organization_id=org.id, ip_address='10.0.0.30')  # no hostname
        db.session.add(asset); db.session.commit()
        asset_id = asset.id

    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/discover', data={'csrf_token': token}, follow_redirects=True)
    assert b'Discovery requires a hostname' in r.data


def test_discovery_confirm_only_adds_explicitly_selected_candidates(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/discover/confirm', data={
        'confirm': ['discovered1.example.com|10.0.0.40|dns_subdomain'],
        'csrf_token': token,
    }, follow_redirects=True)
    assert b'added to scope' in r.data

    from models import Asset
    with as_admin.application.app_context():
        new_asset = Asset.query.filter_by(hostname='discovered1.example.com').first()
        assert new_asset is not None
        assert new_asset.discovered_via == 'dns_subdomain'
        assert new_asset.ip_address == '10.0.0.40'


def test_discovery_confirm_with_no_selections_adds_nothing(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/discover/confirm', data={'csrf_token': token}, follow_redirects=True)
    assert b'0 discovered asset' in r.data


# --- Multi-tenant hosting evidence (§5.7/§14) ------------------------------

def test_marking_shared_hosting_without_evidence_rejected(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/hosting', data={
        'action': 'mark_shared', 'hosting_provider_name': 'Acme Cloud', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'Either a written note or an evidence file is required' in r.data

    from models import Asset
    with as_admin.application.app_context():
        assert Asset.query.get(asset_id).is_shared_hosting is False


def test_marking_shared_hosting_with_note_succeeds(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/hosting', data={
        'action': 'mark_shared', 'hosting_provider_name': 'Acme Cloud',
        'hosting_evidence_note': 'Provider passed independent ASV scan 2026-06-01.',
        'csrf_token': token,
    }, follow_redirects=True)
    assert b'Shared hosting status updated' in r.data

    from models import Asset
    with as_admin.application.app_context():
        asset = Asset.query.get(asset_id)
        assert asset.is_shared_hosting is True
        assert asset.hosting_provider_name == 'Acme Cloud'
        assert 'independent ASV scan' in asset.hosting_evidence_note


def test_marking_shared_hosting_with_file_persists_to_disk(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    r = as_admin.post(f'/assets/{asset_id}/hosting', data={
        'action': 'mark_shared',
        'hosting_evidence_file': (io.BytesIO(b'fake-asv-passing-report'), 'provider_report.pdf'),
        'csrf_token': token,
    }, content_type='multipart/form-data', follow_redirects=True)
    assert b'Shared hosting status updated' in r.data

    import os
    from models import Asset
    with as_admin.application.app_context():
        asset = Asset.query.get(asset_id)
        assert asset.is_shared_hosting is True
        assert asset.hosting_evidence_file_path is not None
        stored = os.path.join(as_admin.application.config['EVIDENCE_UPLOAD_FOLDER'], asset.hosting_evidence_file_path)
        assert os.path.exists(stored)


def test_unmarking_shared_hosting_preserves_evidence(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    as_admin.post(f'/assets/{asset_id}/hosting', data={
        'action': 'mark_shared', 'hosting_evidence_note': 'Verified.', 'csrf_token': token,
    })

    token = get_csrf_token(as_admin, f'/assets/{asset_id}')
    as_admin.post(f'/assets/{asset_id}/hosting', data={'action': 'unmark_shared', 'csrf_token': token})

    from models import Asset
    with as_admin.application.app_context():
        asset = Asset.query.get(asset_id)
        assert asset.is_shared_hosting is False
        assert asset.hosting_evidence_note is not None  # not wiped


def test_asset_detail_page_renders_hosting_section(as_admin, bootstrap):
    asset_id = _make_asset(as_admin, bootstrap)
    r = as_admin.get(f'/assets/{asset_id}')
    assert r.status_code == 200
    assert b'Shared' in r.data
