"""
Shared pytest fixtures.

IMPORTANT: env vars below are set at MODULE IMPORT time, before anything
imports `config`/`app`. config.py's Config class reads os.environ at
class-definition time (i.e. at first `import config`), not per-request --
if any test file imported `app`/`config` before these lines ran, the
DATABASE_URL etc. baked into Config would be wrong for the rest of the
pytest session (module imports are cached; the class body only executes
once). conftest.py is always collected first, so this is the one safe
place to guarantee ordering.

A temp FILE-based SQLite DB is used, not `sqlite:///:memory:`. Several
Celery tasks (scheduler_tick, execute_scan_job, check_scan_schedules,
check_agent_heartbeats) call `create_app()` fresh internally rather than
reusing the caller's app -- with `:memory:`, each new connection gets its
own separate blank database, so nested task calls would silently see an
empty DB. A real file path is shared correctly across all of them.
"""
import os
import tempfile

_db_fd, _DB_PATH = tempfile.mkstemp(suffix='.db')
os.close(_db_fd)
os.environ['DATABASE_URL'] = f'sqlite:///{_DB_PATH}'
os.environ['CELERY_BROKER_URL'] = 'memory://'
os.environ['CELERY_RESULT_BACKEND'] = 'cache+memory://'
os.environ.setdefault('SECRET_KEY', 'test-secret-key-not-for-production')
os.environ['EVIDENCE_UPLOAD_FOLDER'] = tempfile.mkdtemp(prefix='vigilance-test-evidence-')
os.environ['REPORTS_STORAGE_FOLDER'] = tempfile.mkdtemp(prefix='vigilance-test-reports-')

import re
import pytest
import fakeredis

from app import create_app, db as _db
import lock_manager
import tasks as tasks_module


@pytest.fixture(scope='session', autouse=True)
def _celery_eager():
    """Runs every Celery task synchronously in-process, no real broker or
    worker needed. task_eager_propagates=True so a task's exception
    actually surfaces to the test instead of being swallowed."""
    tasks_module.celery.conf.task_always_eager = True
    tasks_module.celery.conf.task_eager_propagates = True


@pytest.fixture(autouse=True)
def _fake_redis():
    """Fresh fakeredis per test -- lock state must never leak between
    tests. Patches the module-level singleton lock_manager.py lazily
    creates on first real use."""
    fake = fakeredis.FakeStrictRedis(decode_responses=True)
    lock_manager._redis_client = fake
    yield fake
    lock_manager._redis_client = None


@pytest.fixture()
def app():
    """Full schema recreation per test function. Slower than
    transaction-rollback isolation, but necessary here: tasks like
    execute_scan_job open their own session (via their own create_app())
    and commit independently of whatever the test's own session is
    doing, so a rollback-based strategy would leak state across tests
    that exercise the scheduler.
    """
    flask_app = create_app()
    with flask_app.app_context():
        _db.drop_all()
        _db.create_all()
        yield flask_app
        _db.session.remove()
        _db.drop_all()


@pytest.fixture()
def db(app):
    return _db


@pytest.fixture()
def client(app):
    return app.test_client()


def get_csrf_token(client, path):
    """Pulls a real CSRF token out of a rendered form -- every POST in
    this app requires one now that CSRF protection is enforced globally.
    """
    resp = client.get(path)
    match = re.search(rb'name="csrf_token" value="([^"]+)"', resp.data)
    assert match, f"no csrf_token found on {path} (status {resp.status_code})"
    return match.group(1).decode()


@pytest.fixture()
def bootstrap(client, db):
    """Creates the first ASV staff account, then onboards one scan
    customer Organization with an admin login. Returns a dict of
    everything most route-level tests need: credentials, IDs, and the
    already-authenticated `client` left logged out (tests log in
    explicitly with whichever role they need).
    """
    from models import User, Organization

    token = get_csrf_token(client, '/setup')
    client.post('/setup', data={
        'email': 'asv@vigilance.example', 'password': 'AsvStaffPass123!', 'csrf_token': token,
    })
    client.get('/logout')

    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': 'asv@vigilance.example', 'password': 'AsvStaffPass123!', 'csrf_token': token,
    })

    token = get_csrf_token(client, '/admin/organizations')
    client.post('/admin/organizations', data={
        'name': 'Acme Retail Co.', 'contact_name': 'Bob Customer', 'email': 'bob@acme.example',
        'admin_email': 'admin@acme.example', 'admin_password': 'AcmeAdminPass123!',
        'csrf_token': token,
    })
    client.get('/logout')

    with client.application.app_context():
        asv_user = User.query.filter_by(email='asv@vigilance.example').first()
        org = Organization.query.filter_by(name='Acme Retail Co.').first()
        admin_user = User.query.filter_by(email='admin@acme.example').first()
        data = {
            'asv_email': 'asv@vigilance.example', 'asv_password': 'AsvStaffPass123!', 'asv_user_id': asv_user.id,
            'org_id': org.id, 'org_name': org.name,
            'admin_email': 'admin@acme.example', 'admin_password': 'AcmeAdminPass123!', 'admin_user_id': admin_user.id,
        }
    return data


@pytest.fixture()
def as_admin(client, bootstrap):
    """Client logged in as the Acme org admin.

    GOTCHA: as_admin and as_asv_staff both authenticate the SAME
    underlying client object (pytest caches `client` once per test, and
    both fixtures depend on it) -- a single session can only be one
    identity at a time, same as a real browser. Do NOT request both
    fixtures in one test signature; the second login attempt will hit
    "already authenticated, redirect to /" and silently break CSRF-token
    extraction. For tests needing two different actors (e.g. customer
    submits a dispute, then ASV staff decides it), use the plain
    `client` + `bootstrap` fixtures and log in/out explicitly within the
    test body instead.
    """
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['admin_email'], 'password': bootstrap['admin_password'], 'csrf_token': token,
    })
    return client


@pytest.fixture()
def as_asv_staff(client, bootstrap):
    """Client logged in as ASV staff. See as_admin's docstring -- do not
    combine with as_admin in the same test."""
    token = get_csrf_token(client, '/login')
    client.post('/login', data={
        'email': bootstrap['asv_email'], 'password': bootstrap['asv_password'], 'csrf_token': token,
    })
    return client
