"""Auth: CSRF enforcement, login, and lockout, exercised through the
real Flask routes."""
from datetime import datetime, timedelta
from tests.conftest import get_csrf_token


def test_setup_redirects_to_login_once_an_account_exists(client, bootstrap):
    r = client.get('/setup', follow_redirects=True)
    assert b'already been completed' in r.data or b'Log In' in r.data or b'log in' in r.data.lower()


def test_setup_cannot_be_repeated(client, bootstrap):
    # /setup redirects once any account exists -- there's no form to pull
    # a CSRF token from, which is itself part of what's being verified.
    r = client.get('/setup')
    assert r.status_code == 302

    r = client.get('/setup', follow_redirects=True)
    assert b'Log In' in r.data or b'log in' in r.data.lower() or b'already been completed' in r.data


def test_csrf_missing_token_rejected_with_400(client, bootstrap):
    r = client.post('/login', data={'email': 'admin@acme.example', 'password': 'AcmeAdminPass123!'})
    assert r.status_code == 400
    assert b'CSRF token is missing' in r.data


def test_csrf_valid_token_accepted(client, bootstrap):
    token = get_csrf_token(client, '/login')
    r = client.post('/login', data={
        'email': 'admin@acme.example', 'password': 'AcmeAdminPass123!', 'csrf_token': token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b'Invalid email or password' not in r.data


def test_wrong_password_shows_generic_message(client, bootstrap):
    token = get_csrf_token(client, '/login')
    r = client.post('/login', data={
        'email': 'admin@acme.example', 'password': 'wrong', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'Invalid email or password' in r.data


def test_nonexistent_email_shows_same_generic_message(client, bootstrap):
    """Must not reveal whether the email exists via a different message."""
    token = get_csrf_token(client, '/login')
    r = client.post('/login', data={
        'email': 'nobody@nowhere.example', 'password': 'whatever', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'Invalid email or password' in r.data


def test_five_failed_attempts_locks_the_account(client, bootstrap):
    from models import User

    for _ in range(4):
        token = get_csrf_token(client, '/login')
        client.post('/login', data={
            'email': 'admin@acme.example', 'password': 'wrong', 'csrf_token': token,
        })
    with client.application.app_context():
        u = User.query.filter_by(email='admin@acme.example').first()
        assert u.is_locked_out is False

    token = get_csrf_token(client, '/login')
    client.post('/login', data={'email': 'admin@acme.example', 'password': 'wrong', 'csrf_token': token})
    with client.application.app_context():
        u = User.query.filter_by(email='admin@acme.example').first()
        assert u.is_locked_out is True


def test_locked_account_rejects_even_the_correct_password(client, bootstrap):
    from models import User

    for _ in range(5):
        token = get_csrf_token(client, '/login')
        client.post('/login', data={'email': 'admin@acme.example', 'password': 'wrong', 'csrf_token': token})

    token = get_csrf_token(client, '/login')
    r = client.post('/login', data={
        'email': 'admin@acme.example', 'password': 'AcmeAdminPass123!', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'Account locked' in r.data


def test_lockout_expiry_allows_login_and_resets_counter(client, bootstrap):
    from models import User
    from app import db

    for _ in range(5):
        token = get_csrf_token(client, '/login')
        client.post('/login', data={'email': 'admin@acme.example', 'password': 'wrong', 'csrf_token': token})

    with client.application.app_context():
        u = User.query.filter_by(email='admin@acme.example').first()
        u.locked_until = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()

    token = get_csrf_token(client, '/login')
    r = client.post('/login', data={
        'email': 'admin@acme.example', 'password': 'AcmeAdminPass123!', 'csrf_token': token,
    }, follow_redirects=True)
    assert r.status_code == 200
    assert b'Invalid' not in r.data
    assert b'Account locked' not in r.data

    with client.application.app_context():
        u = User.query.filter_by(email='admin@acme.example').first()
        assert u.failed_login_attempts == 0
        assert u.locked_until is None


def test_deactivated_account_cannot_log_in(client, bootstrap):
    from models import User
    from app import db

    with client.application.app_context():
        u = User.query.filter_by(email='admin@acme.example').first()
        u.is_active_user = False
        db.session.commit()

    token = get_csrf_token(client, '/login')
    r = client.post('/login', data={
        'email': 'admin@acme.example', 'password': 'AcmeAdminPass123!', 'csrf_token': token,
    }, follow_redirects=True)
    assert b'deactivated' in r.data


def test_logout_then_protected_page_redirects_to_login(client, bootstrap):
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': 'admin@acme.example', 'password': 'AcmeAdminPass123!', 'csrf_token': token,
    })
    client.get('/logout')
    r = client.get('/assets', follow_redirects=True)
    assert b'log in' in r.data.lower() or b'Log In' in r.data
