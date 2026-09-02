"""Distributed scheduler: lock acquisition, retry/backoff, abort-after-
max-attempts, and quarterly scheduling.

IMPORTANT #1: tasks.scheduler_tick / execute_scan_job / check_scan_schedules
each call `create_app()` fresh internally rather than reusing the test's
app instance. Each of those calls gets its own SQLAlchemy session, which
means the test's own `db.session` can hold STALE cached objects after
calling into any of these tasks -- re-querying the same object on the
test's session without invalidating it first can silently return
pre-task data. `db.session.expire_all()` after every task call below is
not decorative.

IMPORTANT #2: create_app() unconditionally seeds two ONLINE agents as a
dev convenience ('Local Celery Worker'/internal, 'Local OpenVAS'/
external) every time it runs, including inside every nested task call
above. This means there is effectively ALWAYS an online agent of both
types available unless a test explicitly takes them offline first --
"no online agent" is not a naturally-occurring state in this app.
"""
from datetime import datetime, timedelta
from unittest.mock import patch

import lock_manager
import tasks


def _seed_asset_and_scan(db, scan_type='external'):
    from models import Organization, Asset, Scan, ScanTarget

    org = Organization(name='TestOrg'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, hostname='target.example.com', ip_address='10.0.0.5')
    db.session.add(asset); db.session.commit()
    scan = Scan(organization_id=org.id, type=scan_type, status='queued')
    db.session.add(scan); db.session.commit()
    db.session.add(ScanTarget(scan_id=scan.id, asset_id=asset.id)); db.session.commit()
    return org.id, asset.id, scan.id


def _patch_all_tools():
    """Every tool-execution function no-op'd so execute_scan_job runs a
    fast, deterministic happy path without needing real nmap/openvas/etc.
    Individual tests override specific ones (e.g. _run_nmap_scan) to test
    failure/retry behavior."""
    from contextlib import ExitStack
    stack = ExitStack()
    stack.enter_context(patch('tasks._run_nmap_scan', return_value=[]))
    stack.enter_context(patch('tasks._run_default_creds_check', return_value=None))
    stack.enter_context(patch('tasks._run_testssl_scan', return_value=None))
    stack.enter_context(patch('tasks._run_zap_scan', return_value=None))
    stack.enter_context(patch('tasks._run_payment_script_check', return_value=None))
    stack.enter_context(patch('tasks._run_nuclei_scan', return_value=None))
    stack.enter_context(patch('tasks._run_openvas_scan', return_value=None))
    stack.enter_context(patch('tasks._check_load_balancer', return_value=None))
    return stack


def test_create_scan_jobs_starts_pending(app, db):
    from models import ScanJob
    _, asset_id, scan_id = _seed_asset_and_scan(db)
    tasks.create_scan_jobs(scan_id, [asset_id])

    jobs = ScanJob.query.filter_by(scan_id=scan_id).all()
    assert len(jobs) == 1
    assert jobs[0].status == 'pending'
    assert jobs[0].attempt_number == 0


def test_happy_path_dispatch_completes_and_releases_lock(app, db):
    from models import ScanJob, Scan, JobExecution

    _, asset_id, scan_id = _seed_asset_and_scan(db)
    tasks.create_scan_jobs(scan_id, [asset_id])

    with _patch_all_tools():
        tasks.scheduler_tick()

    db.session.expire_all()
    job = ScanJob.query.filter_by(scan_id=scan_id).first()
    assert job.status == 'completed'
    assert job.assigned_agent_id is not None
    assert job.attempt_number == 1
    assert job.celery_task_id is not None

    assert lock_manager.is_locked(asset_id) is False

    execs = JobExecution.query.filter_by(scan_job_id=job.id).all()
    assert len(execs) == 1
    assert execs[0].status == 'success'

    scan = Scan.query.get(scan_id)
    assert scan.status == 'completed'
    assert scan.progress_percent == 100
    assert scan.error_message is None


def test_no_online_agent_leaves_job_pending(app, db):
    from models import ScanJob, Agent
    _, asset_id, scan_id = _seed_asset_and_scan(db)

    # The `app` fixture's drop_all() wipes out create_app()'s own initial
    # agent seeding, so the Agent table is genuinely empty at this point
    # -- explicitly recreate both named agents as offline. This matters:
    # if left empty, scheduler_tick's own nested create_app() call would
    # treat it as a real first-time boot and seed them online (correctly,
    # for that scenario), which isn't the condition this test wants to
    # exercise.
    db.session.add(Agent(name='Local Celery Worker', type='internal', status='offline'))
    db.session.add(Agent(name='Local OpenVAS', type='external', status='offline'))
    db.session.commit()

    tasks.create_scan_jobs(scan_id, [asset_id])

    with _patch_all_tools():
        tasks.scheduler_tick()

    db.session.expire_all()
    job = ScanJob.query.filter_by(scan_id=scan_id).first()
    assert job.status == 'pending'
    assert job.attempt_number == 0


def test_lock_contention_does_not_consume_an_attempt(app, db):
    from models import ScanJob
    _, asset_id, scan_id = _seed_asset_and_scan(db)
    tasks.create_scan_jobs(scan_id, [asset_id])

    foreign_token = lock_manager.acquire_lock(asset_id)
    assert foreign_token is not None

    with _patch_all_tools():
        tasks.scheduler_tick()

    db.session.expire_all()
    job = ScanJob.query.filter_by(scan_id=scan_id).first()
    assert job.status == 'pending'
    assert job.attempt_number == 0  # lock contention burned NO attempt

    lock_manager.release_lock(asset_id, foreign_token)


def test_retry_backoff_then_eventual_success(app, db):
    from models import ScanJob, JobExecution

    _, asset_id, scan_id = _seed_asset_and_scan(db)
    tasks.create_scan_jobs(scan_id, [asset_id])

    call_count = {'n': 0}
    def flaky_nmap(scan_id_, asset_id_, target, db_, Finding):
        call_count['n'] += 1
        if call_count['n'] < 3:
            raise Exception(f"simulated failure #{call_count['n']}")
        return []

    with patch('tasks._run_nmap_scan', side_effect=flaky_nmap), \
         patch('tasks._run_default_creds_check', return_value=None), \
         patch('tasks._run_testssl_scan', return_value=None), \
         patch('tasks._run_zap_scan', return_value=None), \
         patch('tasks._run_payment_script_check', return_value=None), \
         patch('tasks._run_nuclei_scan', return_value=None), \
         patch('tasks._run_openvas_scan', return_value=None), \
         patch('tasks._check_load_balancer', return_value=None):

        # Attempt 1: fails
        tasks.scheduler_tick()
        db.session.expire_all()
        job = ScanJob.query.filter_by(scan_id=scan_id).first()
        assert job.status == 'retry_scheduled'
        assert job.attempt_number == 1
        backoff = (job.next_retry_at - datetime.utcnow()).total_seconds()
        assert 0 < backoff <= tasks.RETRY_BACKOFF_SECONDS[0] + 1

        # Not due yet -- scheduler must ignore it
        tasks.scheduler_tick()
        db.session.expire_all()
        job = ScanJob.query.filter_by(scan_id=scan_id).first()
        assert job.attempt_number == 1  # unchanged

        assert lock_manager.is_locked(asset_id) is False  # released even on failure

        # Force due, attempt 2: fails again
        job.next_retry_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        tasks.scheduler_tick()
        db.session.expire_all()
        job = ScanJob.query.filter_by(scan_id=scan_id).first()
        assert job.status == 'retry_scheduled'
        assert job.attempt_number == 2

        # Force due, attempt 3: succeeds
        job.next_retry_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
        tasks.scheduler_tick()
        db.session.expire_all()
        job = ScanJob.query.filter_by(scan_id=scan_id).first()
        assert job.status == 'completed'
        assert job.attempt_number == 3

    execs = JobExecution.query.filter_by(scan_job_id=job.id).order_by(JobExecution.attempt_number).all()
    assert len(execs) == 3
    assert [e.status for e in execs] == ['failed', 'failed', 'success']
    assert 'simulated failure #1' in execs[0].error_message
    assert 'simulated failure #2' in execs[1].error_message


def test_abort_after_max_attempts(app, db):
    from models import ScanJob, Scan

    _, asset_id, scan_id = _seed_asset_and_scan(db)
    tasks.create_scan_jobs(scan_id, [asset_id])

    with patch('tasks._run_nmap_scan', side_effect=Exception("permanent failure")), \
         patch('tasks._run_default_creds_check', return_value=None), \
         patch('tasks._run_testssl_scan', return_value=None), \
         patch('tasks._run_zap_scan', return_value=None), \
         patch('tasks._run_payment_script_check', return_value=None), \
         patch('tasks._run_nuclei_scan', return_value=None), \
         patch('tasks._run_openvas_scan', return_value=None), \
         patch('tasks._check_load_balancer', return_value=None):

        for _ in range(5):
            db.session.expire_all()
            job = ScanJob.query.filter_by(scan_id=scan_id).first()
            if job.next_retry_at:
                job.next_retry_at = datetime.utcnow() - timedelta(seconds=1)
                db.session.commit()
            tasks.scheduler_tick()

        db.session.expire_all()
        job = ScanJob.query.filter_by(scan_id=scan_id).first()
        assert job.status == 'aborted'
        assert job.attempt_number == 5

        # A 6th tick must not touch it again -- it's terminal.
        tasks.scheduler_tick()
        db.session.expire_all()
        job = ScanJob.query.filter_by(scan_id=scan_id).first()
        assert job.attempt_number == 5

    assert lock_manager.is_locked(asset_id) is False

    scan = Scan.query.get(scan_id)
    assert scan.status == 'completed'  # rolled up, not stuck 'running'
    assert scan.error_message is not None
    assert 'aborted' in scan.error_message.lower()


def test_quarterly_schedule_creates_scan_for_in_scope_assets_only(app, db):
    from models import Organization, Asset, ScanSchedule, Scan, ScanJob

    org = Organization(name='ScheduleOrg'); db.session.add(org); db.session.commit()
    in_scope = Asset(organization_id=org.id, hostname='in.example.com', ip_address='10.0.0.1')
    excluded = Asset(organization_id=org.id, hostname='out.example.com', ip_address='10.0.0.2',
                      is_out_of_scope=True, segmentation_attestation='VLAN isolated')
    db.session.add_all([in_scope, excluded]); db.session.commit()

    schedule = ScanSchedule(organization_id=org.id, scan_type='external', frequency='quarterly',
                             next_run=datetime.utcnow() - timedelta(hours=1), enabled=True)
    db.session.add(schedule); db.session.commit()
    schedule_id, org_id, in_scope_id = schedule.id, org.id, in_scope.id

    scans_before = Scan.query.filter_by(organization_id=org_id).count()
    tasks.check_scan_schedules()
    db.session.expire_all()

    scans_after = Scan.query.filter_by(organization_id=org_id).count()
    assert scans_after == scans_before + 1

    new_scan = Scan.query.filter_by(organization_id=org_id).order_by(Scan.id.desc()).first()
    jobs = ScanJob.query.filter_by(scan_id=new_scan.id).all()
    assert len(jobs) == 1
    assert jobs[0].asset_id == in_scope_id  # excluded asset correctly skipped


def test_quarterly_schedule_advances_next_run_and_does_not_double_fire(app, db):
    from models import Organization, Asset, ScanSchedule, Scan

    org = Organization(name='ScheduleOrg2'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, hostname='x.example.com', ip_address='10.0.0.1')
    db.session.add(asset); db.session.commit()

    schedule = ScanSchedule(organization_id=org.id, scan_type='external', frequency='quarterly',
                             next_run=datetime.utcnow() - timedelta(hours=1), enabled=True)
    db.session.add(schedule); db.session.commit()
    schedule_id, org_id = schedule.id, org.id

    tasks.check_scan_schedules()
    db.session.expire_all()

    schedule = ScanSchedule.query.get(schedule_id)
    assert schedule.last_run is not None
    expected_next = schedule.last_run + timedelta(days=90)
    assert abs((schedule.next_run - expected_next).total_seconds()) < 2

    scans_before = Scan.query.filter_by(organization_id=org_id).count()
    tasks.check_scan_schedules()
    db.session.expire_all()
    scans_after = Scan.query.filter_by(organization_id=org_id).count()
    assert scans_after == scans_before  # next_run is now in the future -- must not re-fire


def test_disabled_schedule_never_fires(app, db):
    from models import Organization, Asset, ScanSchedule, Scan

    org = Organization(name='ScheduleOrg3'); db.session.add(org); db.session.commit()
    asset = Asset(organization_id=org.id, hostname='y.example.com', ip_address='10.0.0.1')
    db.session.add(asset); db.session.commit()

    schedule = ScanSchedule(organization_id=org.id, scan_type='external', frequency='quarterly',
                             next_run=datetime.utcnow() - timedelta(hours=1), enabled=False)
    db.session.add(schedule); db.session.commit()
    org_id = org.id

    scans_before = Scan.query.filter_by(organization_id=org_id).count()
    tasks.check_scan_schedules()
    db.session.expire_all()
    assert Scan.query.filter_by(organization_id=org_id).count() == scans_before


def test_stale_agent_heartbeat_marked_offline(app, db):
    from models import Agent

    with app.app_context():
        stale = Agent(name='Stale External Agent', type='external', status='online',
                       last_seen=datetime.utcnow() - timedelta(seconds=tasks.AGENT_HEARTBEAT_TIMEOUT_SECONDS + 30))
        db.session.add(stale); db.session.commit()
        stale_id = stale.id

    tasks.check_agent_heartbeats()
    db.session.expire_all()

    assert Agent.query.get(stale_id).status == 'offline'


def test_fresh_agent_heartbeat_stays_online(app, db):
    from models import Agent

    with app.app_context():
        fresh = Agent(name='Fresh External Agent', type='external', status='online',
                       last_seen=datetime.utcnow())
        db.session.add(fresh); db.session.commit()
        fresh_id = fresh.id

    tasks.check_agent_heartbeats()
    db.session.expire_all()

    assert Agent.query.get(fresh_id).status == 'online'
