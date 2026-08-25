import os
import json
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

import requests
from celery import Celery
from config import Config

import cvss_engine
import eol_os
import lock_manager
from default_creds import run_default_creds_scan

# Initialize Celery app
celery = Celery(
    'tasks',
    broker=Config.CELERY_BROKER_URL,
    backend=Config.CELERY_RESULT_BACKEND
)

# Orchestration engine doc §13/§19: the scheduler evaluates pending/
# retry-eligible jobs on a short fixed interval, and quarterly-schedule
# due-checks run far less often since the coarsest schedule granularity
# is weekly. Run `celery -A tasks.celery beat` alongside the worker for
# these to actually fire -- a worker process alone does not execute
# beat_schedule entries.
celery.conf.beat_schedule = {
    'scheduler-tick': {'task': 'tasks.scheduler_tick', 'schedule': 5.0},
    'check-scan-schedules': {'task': 'tasks.check_scan_schedules', 'schedule': 3600.0},
    'check-agent-heartbeats': {'task': 'tasks.check_agent_heartbeats', 'schedule': 30.0},
}
celery.conf.timezone = 'UTC'

# Orchestration doc §22: "If heartbeat timeout exceeds 90 seconds, Agent
# status becomes offline. Scheduler immediately stops assigning new jobs."
# Nothing previously enforced this -- an agent whose process crashed
# without a clean shutdown would sit 'online' forever, and scheduler_tick
# would keep trying to hand it work indefinitely.
AGENT_HEARTBEAT_TIMEOUT_SECONDS = 90

# §19 Retry Strategy exact table: 2, 4, 8, 16, 30s (capped).
RETRY_BACKOFF_SECONDS = [2, 4, 8, 16, 30]
MAX_ATTEMPTS = 5

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

# PCI §6.8/§7: proportion of scanned ports returning 'filtered' (vs a
# definitive open/closed state) above which a scan is treated as
# inconclusive -- i.e. an active protection system is silently dropping
# probes rather than actually being an unprotected, mostly-closed host.
FILTERED_RATIO_INCONCLUSIVE_THRESHOLD = 0.90


def _make_finding(db, Finding, scan_id, asset_id, severity, cve, description,
                   recommendation, source_tool, is_auto_fail=False):
    """Single choke point for creating a Finding. Every finding, regardless
    of which tool produced it, gets its CVSS score resolved here through
    the NVD-backed engine (cvss_engine.py) rather than trusting whatever
    severity label the source tool assigned — see architecture doc
    correction #4. Findings without a CVE fall back to a conservative
    CVSS-equivalent band derived from `severity`.
    """
    from models import CveCache
    score, source = cvss_engine.resolve_cvss(cve, db, CveCache, severity_hint=severity)
    return Finding(
        scan_id=scan_id, asset_id=asset_id, severity=severity, cve=cve or '',
        description=description, recommendation=recommendation,
        source_tool=source_tool, is_auto_fail=is_auto_fail,
        cvss_score=score, cvss_source=source,
    )


def create_scan_jobs(scan_id, asset_ids):
    """Plain DB write, not a Celery task -- decomposing a Scan into
    per-asset ScanJobs (orchestration doc §14) is trivial and synchronous;
    only the actual scanning work needs to go through Celery. Jobs start
    in 'pending' and are picked up by scheduler_tick, not dispatched
    directly here -- the scheduler is the single place that decides when
    a job is actually allowed to run (lock + agent availability).
    """
    from app import db
    from models import ScanJob
    for asset_id in asset_ids:
        db.session.add(ScanJob(scan_id=scan_id, asset_id=asset_id, status='pending'))
    db.session.commit()


def _recompute_scan_status(scan, db):
    """Rolls the parent Scan's status/progress up from its ScanJobs.
    Called after every job state transition. Reuses the existing
    queued/running/completed/failed vocabulary rather than introducing
    new Scan-level states -- a scan with some aborted jobs is reported as
    'completed' with error_message populated (existing §9.1 Full/Partial
    logic in routes.py already reads error_message to distinguish that).
    """
    from models import ScanJob
    jobs = ScanJob.query.filter_by(scan_id=scan.id).all()
    if not jobs:
        return

    statuses = {j.status for j in jobs}
    non_terminal = {'pending', 'running', 'retry_scheduled'}

    if statuses & non_terminal:
        scan.status = 'running'
        done = sum(1 for j in jobs if j.status in ('completed', 'failed', 'aborted'))
        scan.progress_percent = int(5 + 90 * (done / len(jobs)))
        scan.progress = f"{done}/{len(jobs)} asset jobs finished"
    else:
        aborted = [j for j in jobs if j.status == 'aborted']
        inconclusive = [j for j in jobs if j.is_inconclusive]
        scan.status = 'completed'
        scan.progress_percent = 100
        notes = []
        if aborted:
            asset_ids = ', '.join(str(j.asset_id) for j in aborted)
            notes.append(f"{len(aborted)} of {len(jobs)} asset job(s) exhausted all retry "
                         f"attempts and were aborted (asset IDs: {asset_ids})")
        if inconclusive:
            asset_ids = ', '.join(str(j.asset_id) for j in inconclusive)
            notes.append(f"{len(inconclusive)} asset job(s) returned an inconclusive scan due to "
                         f"active protection system interference (asset IDs: {asset_ids})")
        if notes:
            scan.error_message = '; '.join(notes) + '. Scan is Partial.'
            scan.progress = f"Completed with {len(aborted)} aborted, {len(inconclusive)} inconclusive job(s)"
        else:
            scan.progress = "Completed"
        scan.end_time = datetime.utcnow()


@celery.task
def check_agent_heartbeats():
    """Orchestration doc §22: agents whose last heartbeat is older than
    AGENT_HEARTBEAT_TIMEOUT_SECONDS are marked offline, so scheduler_tick's
    `Agent.query.filter_by(type=..., status='online')` never hands work to
    a process that's actually dead. Runs every 30s -- frequent enough that
    a genuinely crashed agent is caught within one heartbeat-timeout
    window, not several scheduler ticks later.
    """
    from app import create_app, db
    from models import Agent

    app = create_app()
    with app.app_context():
        cutoff = datetime.utcnow() - timedelta(seconds=AGENT_HEARTBEAT_TIMEOUT_SECONDS)
        stale = Agent.query.filter(Agent.status == 'online', Agent.last_seen < cutoff).all()
        for agent in stale:
            agent.status = 'offline'
        if stale:
            db.session.commit()


@celery.task
def scheduler_tick():
    """The scheduler (orchestration doc §12/§18/§20). Runs every 5s via
    Celery Beat. This is the ONLY place that dispatches a ScanJob to a
    worker -- jobs never self-schedule. Each tick:

        1. Fetch every job in 'pending' or 'retry_scheduled' (whose
           next_retry_at has passed), ordered by priority then age.
        2. For each: try to find an online Agent matching the scan's
           type, and try to acquire that asset's Redis lock.
        3. Only if BOTH succeed does the job get dispatched
           (execute_scan_job.delay) and marked 'running'.
        4. Otherwise the job is left exactly as it was for the next tick
           -- no attempt is consumed by lock contention or agent
           unavailability. attempt_number only increases on an actual
           execution failure (see execute_scan_job), matching §19's
           retry table being about failed *executions*, not queueing
           delay. This is Strategy 3 (Non-Blocking Lock) from §15: the
           scheduler never blocks waiting for a lock, it just tries the
           next job.
    """
    from app import create_app, db
    from models import ScanJob, Scan, Agent

    app = create_app()
    with app.app_context():
        now = datetime.utcnow()
        candidates = ScanJob.query.filter(
            db.or_(
                ScanJob.status == 'pending',
                db.and_(ScanJob.status == 'retry_scheduled', ScanJob.next_retry_at <= now)
            )
        ).order_by(ScanJob.priority.asc(), ScanJob.created_at.asc()).all()

        for job in candidates:
            scan = Scan.query.get(job.scan_id)
            if not scan:
                continue

            agent = Agent.query.filter_by(type=scan.type, status='online').first()
            if not agent:
                continue  # no capacity right now -- try again next tick

            token = lock_manager.acquire_lock(job.asset_id)
            if not token:
                continue  # another job is currently working this asset -- try again next tick

            job.status = 'running'
            job.assigned_agent_id = agent.id
            job.started_at = now
            job.attempt_number += 1
            db.session.commit()

            async_result = execute_scan_job.delay(job.id, token)
            job.celery_task_id = async_result.id
            db.session.commit()


@celery.task
def check_scan_schedules():
    """PCI reference doc §10: quarterly scan cadence. Runs hourly (fine
    granularity isn't needed -- the coarsest frequency is weekly). Any
    ScanSchedule whose next_run has passed gets turned into a real Scan
    covering every currently in-scope Asset for that organization, then
    next_run/last_run are advanced.
    """
    from app import create_app, db
    from models import ScanSchedule, Scan, Asset, ScanTarget

    app = create_app()
    with app.app_context():
        now = datetime.utcnow()
        due = ScanSchedule.query.filter(
            ScanSchedule.enabled == True,  # noqa: E712
            ScanSchedule.next_run <= now
        ).all()

        for schedule in due:
            in_scope_assets = Asset.query.filter_by(
                organization_id=schedule.organization_id, is_out_of_scope=False
            ).all()

            if in_scope_assets:
                scan = Scan(organization_id=schedule.organization_id, type=schedule.scan_type, status='queued')
                db.session.add(scan)
                db.session.flush()
                for asset in in_scope_assets:
                    db.session.add(ScanTarget(scan_id=scan.id, asset_id=asset.id))
                db.session.commit()
                create_scan_jobs(scan.id, [a.id for a in in_scope_assets])

            schedule.last_run = now
            if schedule.frequency == 'weekly':
                schedule.next_run = now + timedelta(weeks=1)
            elif schedule.frequency == 'monthly':
                schedule.next_run = now + timedelta(days=30)
            else:  # quarterly -- matches PCI's "at least once every three months"
                schedule.next_run = now + timedelta(days=90)
            db.session.commit()


@celery.task(bind=True)
def execute_scan_job(self, job_id, lock_token):
    """Runs one asset's full pipeline. This is the direct successor to
    the old execute_scan's per-asset loop body -- the tool-execution
    logic (_run_nmap_scan etc.) is completely unchanged, only the
    surrounding job-lifecycle/locking/retry machinery is new.
    """
    from app import create_app, db
    from models import ScanJob, Scan, Asset, Finding, JobExecution

    app = create_app()
    with app.app_context():
        job = ScanJob.query.get(job_id)
        if not job:
            # Should never happen in practice. We don't know the asset_id
            # without the job row, so we can't release the lock directly --
            # its TTL (§15 Strategy 4) is the safety net here.
            print(f"execute_scan_job: ScanJob {job_id} no longer exists, relying on lock TTL expiry")
            return

        scan = Scan.query.get(job.scan_id)
        asset = Asset.query.get(job.asset_id)

        execution = JobExecution(
            scan_job_id=job.id, agent_id=job.assigned_agent_id,
            attempt_number=job.attempt_number, started_at=datetime.utcnow(), status='running'
        )
        db.session.add(execution)
        db.session.commit()

        if scan.start_time is None:
            scan.start_time = datetime.utcnow()
            scan.status = 'running'
            db.session.commit()

        try:
            if not asset:
                raise Exception(f"Asset {job.asset_id} no longer exists")

            target = asset.ip_address or asset.hostname
            if not target:
                raise Exception(f"Asset {job.asset_id} has no IP or hostname to scan")

            # Nmap always runs first -- baseline discovery layer (PCI
            # §5.1-5.3); everything downstream targets the ports it finds.
            open_ports = _run_nmap_scan(scan.id, asset.id, target, db, Finding)

            # PCI §5.5: multiple DNS A records for this asset's hostname
            # is the standard load-balancer signal. Needs a real hostname
            # (not just an IP) to be meaningful, and only applies to
            # external scans -- internal assets are typically addressed
            # by IP directly, without a public-facing load balancer.
            if scan.type == 'external' and asset.hostname:
                _check_load_balancer(scan.id, asset.id, asset.hostname, db, Finding)

            # PCI §6.1: known vendor default accounts/passwords, tested
            # (not brute-forced) against services Nmap found open.
            _run_default_creds_check(scan.id, asset.id, target, open_ports, db, Finding)

            if scan.type == 'external':
                _run_testssl_scan(scan.id, asset.id, target, open_ports, db, Finding)
                _run_zap_scan(scan.id, asset.id, target, open_ports, db, Finding)
                _run_payment_script_check(scan.id, asset.id, target, open_ports, db, Finding)
                _run_nuclei_scan(scan.id, asset.id, target, db, Finding)
                _run_openvas_scan(scan.id, asset.id, target, db, Finding)
            else:
                _run_openvas_scan(scan.id, asset.id, target, db, Finding)
                _run_nuclei_scan(scan.id, asset.id, target, db, Finding)

            job.status = 'completed'
            job.completed_at = datetime.utcnow()
            job.error_message = None
            execution.status = 'success'
            execution.completed_at = datetime.utcnow()

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            print(f"Error executing ScanJob {job.id} (attempt {job.attempt_number}):\n{error_trace}")

            execution.status = 'failed'
            execution.error_message = f"{e}\n\n{error_trace}"
            execution.completed_at = datetime.utcnow()
            job.error_message = str(e)

            if job.attempt_number >= job.max_attempts:
                # §19: "Attempts >= Max -> Abort Job"
                job.status = 'aborted'
                job.completed_at = datetime.utcnow()
            else:
                # §19 exact backoff table: 2, 4, 8, 16, 30s. The scheduler
                # (not Celery's own countdown) re-evaluates this job once
                # next_retry_at passes -- see scheduler_tick's docstring.
                backoff = RETRY_BACKOFF_SECONDS[min(job.attempt_number - 1, len(RETRY_BACKOFF_SECONDS) - 1)]
                job.status = 'retry_scheduled'
                job.next_retry_at = datetime.utcnow() + timedelta(seconds=backoff)

        finally:
            # Lock release always happens, success or failure, so the
            # next attempt (or a different job entirely) can proceed.
            # TTL expiry is only the crash-safety fallback (§15 Strategy
            # 4) -- this is the primary release path.
            lock_manager.release_lock(job.asset_id, lock_token)
            _recompute_scan_status(scan, db)
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

                finding = _make_finding(
                    db, Finding,
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


def _run_default_creds_check(scan_id, asset_id, target, open_ports, db, Finding):
    """PCI §6.1 (exact wording): 'Detect the presence of built-in or default
    accounts and passwords... Any such vulnerability must be marked as an
    automatic failure by the ASV.' See default_creds.py docstring for why
    this is a single-attempt-per-pair check, not brute force.
    """
    from models import Scan
    scan = Scan.query.get(scan_id)
    scan.progress = f"Checking default credentials on {target}..."
    db.session.commit()

    web_ports = [p['port'] for p in open_ports if p['port'] in WEB_PORTS or p['service'] in ('http', 'https')]

    try:
        hits = run_default_creds_scan(target, open_ports, web_scheme='http', web_ports=web_ports)
    except Exception as e:
        print(f"Default-credential check error for {target}: {e}")
        return

    for hit in hits:
        db.session.add(_make_finding(
            db, Finding, scan_id=scan.id, asset_id=asset_id, severity='Critical', cve='',
            description=(
                f"{hit['service']} on port {hit['port']} accepted a known vendor default "
                f"credential (username: {hit['username']}). {hit['note']}"
            ),
            recommendation="Change the default credential immediately and disable the account if unused.",
            source_tool='default-creds-check',
            is_auto_fail=True,  # PCI §6.1 / §7: default credentials are an explicit auto-fail
        ))
    if hits:
        db.session.commit()


def _run_nmap_scan(scan_id, asset_id, target, db, Finding):
    """Baseline discovery layer (PCI §5.1-5.3): live host, full TCP port range,
    service/version detection, OS fingerprinting, and NSE vuln + DNS
    zone-transfer scripts. Returns the list of open ports so downstream tools
    (testssl.sh, ZAP) know what to target instead of re-discovering it.
    """
    from models import Scan, ScanJob
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

            # PCI §6.8/§7/§14: "If active protection systems dynamically
            # block ASV traffic... it results in an inconclusive scan...
            # the ASV must record the scan as a failure and describe the
            # interference." A stateful firewall/IPS silently dropping
            # probes (rather than responding with a real open/closed
            # state) shows up as most-or-all ports coming back 'filtered'
            # -- a live, unprotected host normally resolves the vast
            # majority of its 65535 ports to a definitive open/closed
            # state. The 100-port floor avoids flagging narrow/manual
            # scans where a handful of filtered ports is unremarkable.
            all_ports = host.findall('.//port')
            total_scanned = len(all_ports)
            filtered_count = sum(
                1 for p in all_ports
                if p.find('state') is not None and p.find('state').get('state') == 'filtered'
            )
            host_status = host.find('status')
            host_is_down = host_status is not None and host_status.get('state') == 'down'

            inconclusive_reason = None
            if host_is_down:
                inconclusive_reason = "Host did not respond to any probes -- traffic appears to have been silently dropped."
            elif total_scanned >= 100:
                filtered_ratio = filtered_count / total_scanned
                if filtered_ratio >= FILTERED_RATIO_INCONCLUSIVE_THRESHOLD:
                    inconclusive_reason = (
                        f"{filtered_count}/{total_scanned} scanned ports ({filtered_ratio:.0%}) "
                        f"returned 'filtered' rather than a definitive open/closed state."
                    )

            if inconclusive_reason:
                db.session.add(_make_finding(
                    db, Finding, scan_id=scan.id, asset_id=asset_id, severity='High', cve='',
                    description=(
                        f"Inconclusive scan (§6.8/§7): {inconclusive_reason} This pattern indicates "
                        f"an active protection system (WAF/IPS/firewall) is blocking or filtering "
                        f"ASV scan traffic. Per PCI reference doc §7, an inconclusive scan must be "
                        f"recorded as an automatic failure until resolved."
                    ),
                    recommendation=(
                        "Temporarily configure active protection systems to monitor/log-only for "
                        "the ASV's scanning IP addresses, or provide written evidence the scan "
                        "wasn't blocked, or establish a secure tunnel / install a local scanning "
                        "appliance behind the block."
                    ),
                    source_tool='nmap', is_auto_fail=True
                ))
                job = ScanJob.query.filter_by(scan_id=scan_id, asset_id=asset_id).first()
                if job:
                    # Not retried -- re-running Nmap against the same
                    # firewall produces the same result, so this doesn't
                    # burn the job's retry attempts the way a transient
                    # tool crash does. The job still "completes"; the
                    # auto-fail finding above is the actual outcome.
                    job.is_inconclusive = True
                db.session.commit()

            for port_el in host.findall('.//port'):
                state = port_el.find('state')
                if state is None or state.get('state') != 'open':
                    continue

                port_id = int(port_el.get('portid'))
                proto = port_el.get('protocol')
                service_el = port_el.find('service')
                service_name = service_el.get('name') if service_el is not None else 'unknown'

                open_ports.append({'port': port_id, 'proto': proto, 'service': service_name})

                # PCI §6.7: "If the ASV detects open ports but cannot
                # remotely fingerprint or identify the protocol or
                # service, it must flag them as 'unknown services'."
                # Nmap itself uses the literal string 'unknown' (or omits
                # the <service> element entirely) when -sV can't identify
                # what's listening -- this was previously discarded
                # silently since it doesn't match any of the specific
                # checks below.
                if service_name in ('unknown', 'tcpwrapped') or service_el is None:
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id, severity='Low', cve='',
                        description=(
                            f"Unknown service on port {port_id}/{proto} -- Nmap could not remotely "
                            f"fingerprint the protocol or application listening on this port."
                        ),
                        recommendation=(
                            "Investigate to rule out malware/rootkits; justify the business need for "
                            "this port and confirm secure implementation, or disable it if unused."
                        ),
                        source_tool='nmap', is_auto_fail=False
                    ))

                # PCI 1.4.4 / §6.6 — databases exposed to the Internet: auto-fail
                if port_id in DB_PORTS:
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id, severity='High', cve='',
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
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id,
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
                        db.session.add(_make_finding(
                            db, Finding, scan_id=scan.id, asset_id=asset_id, severity='High', cve='',
                            description=f"Nmap NSE [{script_id}] on port {port_id}/{proto}: {output[:500]}",
                            recommendation="Review and remediate per NSE script guidance.",
                            source_tool='nmap',
                            # PCI §6/§7: unrestricted DNS zone transfer is an explicit auto-fail
                            is_auto_fail=is_zone_transfer
                        ))

            if os_name:
                # PCI §7 (exact wording): "Determining the OS is a version no
                # longer supported by the vendor... must be marked as an
                # automatic failure." eol_os.check_eol matches the free-text
                # Nmap fingerprint against a curated EOL table; an unmatched
                # string means "unknown," not "safe," so it's still logged,
                # just not auto-failed.
                eol_info = eol_os.check_eol(os_name)
                if eol_info and eol_info['is_eol']:
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id, severity='High', cve='',
                        description=(
                            f"OS fingerprint: {os_name} — matched {eol_info['matched_name']}, "
                            f"end-of-life as of {eol_info['eol_date'].isoformat()}. Unsupported "
                            f"operating systems no longer receive vendor security patches."
                        ),
                        recommendation="Upgrade to a currently supported OS version.",
                        source_tool='nmap', is_auto_fail=True
                    ))
                else:
                    note = (
                        f"(EOL {eol_info['eol_date'].isoformat()}, still within support window)"
                        if eol_info else "(support status not determined against known EOL table)"
                    )
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id, severity='Informational', cve='',
                        description=f"OS fingerprint: {os_name} {note}", recommendation='',
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

    def _testssl_indicates_present(text):
        """testssl.sh consistently phrases a clean result as 'not
        offered'/'not vulnerable' and a hit as 'offered'/'VULNERABLE' --
        same presence heuristic the early-TLS-protocol check above
        already relies on, generalized here for the ADH/SHA-1 checks."""
        t = text.lower()
        if 'not offered' in t or 'not vulnerable' in t:
            return False
        return 'offered' in t or 'vulnerable' in t

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
                text_lower = finding_text.lower()

                is_early_protocol_offered = (
                    entry_id in AUTO_FAIL_PROTOCOL_IDS
                    and 'not offered' not in text_lower
                    and 'offered' in text_lower
                )

                if severity_raw in ('CRITICAL', 'HIGH') or is_early_protocol_offered:
                    severity = 'Critical' if severity_raw == 'CRITICAL' else 'High'
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id, severity=severity, cve='',
                        description=f"testssl.sh [{entry_id}] on port {port}: {finding_text}",
                        recommendation="Disable SSL/early TLS; support TLS 1.2+ only with strong cipher suites.",
                        source_tool='testssl',
                        is_auto_fail=is_early_protocol_offered
                    ))
                    continue

                # §6.2 Special Notes: these are typically MEDIUM/LOW (or
                # even INFO) in testssl.sh's own severity scale, so the
                # CRITICAL/HIGH filter above silently dropped every one of
                # them -- they were never becoming findings at all, not
                # even visible ones. Not an auto-fail condition per the
                # reference doc; still a real finding a customer needs to
                # see and justify/remediate.
                is_adh = ('adh' in text_lower or 'aecdh' in text_lower) and _testssl_indicates_present(finding_text)
                is_deprecated_crypto = (
                    ('sha1' in text_lower.replace('-', '').replace(' ', '') or 'sha-1' in text_lower)
                    and _testssl_indicates_present(finding_text)
                )

                if is_adh:
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id, severity='Medium', cve='',
                        description=(
                            f"testssl.sh [{entry_id}] on port {port}: {finding_text} -- Special Note (§6.2): "
                            f"Anonymous Diffie-Hellman key exchange increases man-in-the-middle risk."
                        ),
                        recommendation="Disable ADH/AECDH cipher suites; require authenticated key exchange.",
                        source_tool='testssl', is_auto_fail=False
                    ))
                elif is_deprecated_crypto:
                    db.session.add(_make_finding(
                        db, Finding, scan_id=scan.id, asset_id=asset_id, severity='Medium', cve='',
                        description=(
                            f"testssl.sh [{entry_id}] on port {port}: {finding_text} -- Special Note (§6.2): "
                            f"industry-deprecated cryptographic algorithm (SHA-1) in use."
                        ),
                        recommendation="Reissue certificates/configure services to use SHA-256 or stronger.",
                        source_tool='testssl', is_auto_fail=False
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

            db.session.add(_make_finding(
                db, Finding, scan_id=scan.id, asset_id=asset_id, severity=severity, cve='',
                description=f"ZAP: {name} — {desc[:400]}",
                recommendation=solution[:500],
                source_tool='zap', is_auto_fail=is_auto_fail
            ))

        db.session.commit()
    except Exception as e:
        # Non-fatal by design — see docstring.
        print(f"ZAP scan error for {target_url}: {e}")


# Common tag-management/analytics/advertising script hosts. §6.5 is about
# ANY third-party script executing in the consumer's browser, not just
# these -- this list catches the overwhelmingly common cases (matches the
# same "curated, not exhaustive" approach as default_creds.py's vendor
# list) so a real hit doesn't get lost in noise from every <script> tag
# on the page.
PAYMENT_SCRIPT_HOST_PATTERNS = (
    'googletagmanager.com', 'google-analytics.com', 'googlesyndication.com',
    'doubleclick.net', 'facebook.net', 'connect.facebook.net', 'hotjar.com',
    'segment.com', 'segment.io', 'mixpanel.com', 'fullstory.com',
    'clarity.ms', 'criteo.com', 'adroll.com', 'taboola.com', 'outbrain.com',
    'tiktok.com/i18n', 'analytics.tiktok.com', 'snap.licdn.com',
    'bat.bing.com', 'amplitude.com', 'intercom.io', 'drift.com',
)


def _run_payment_script_check(scan_id, asset_id, target, open_ports, db, Finding):
    """PCI §6.5 (exact wording): 'The ASV scan must detect scripts loaded
    and executed in the consumer's browser (e.g., advertising, tracking,
    tag management systems). Detection triggers a Special Note requiring
    the customer to justify the business need and ensure explicit
    authorization/secure implementation... relates to PCI DSS Requirements
    6.4.3 and 11.6.1.'

    Uses a real headless browser (same Playwright dependency discovery.py
    already needs for JS-redirect tracking) rather than static HTML
    parsing, because §6.5 explicitly means scripts that actually EXECUTE
    in the browser -- many tag-manager scripts are injected dynamically
    by other scripts, not present in the page's raw HTML at all.
    """
    from models import Scan
    scan = Scan.query.get(scan_id)

    web_ports = [p['port'] for p in open_ports if p['port'] in WEB_PORTS or p['service'] in ('http', 'https')]
    if not web_ports:
        return

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("Playwright not installed -- skipping payment page script check (§6.5)")
        return

    scan.progress = f"Checking for third-party page scripts on {target}..."
    db.session.commit()

    seen_hosts = set()
    for port in web_ports:
        scheme = 'https' if port in TLS_PORTS else 'http'
        port_suffix = '' if port in (80, 443) else f':{port}'
        url = f"{scheme}://{target}{port_suffix}"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch()
                try:
                    page = browser.new_page(ignore_https_errors=True)
                    page.goto(url, timeout=15000, wait_until='networkidle')
                    script_srcs = page.eval_on_selector_all('script[src]', 'els => els.map(e => e.src)')
                finally:
                    browser.close()
        except Exception as e:
            print(f"Payment script check failed for {url}: {e}")
            continue

        from urllib.parse import urlparse
        for src in script_srcs:
            host = urlparse(src).hostname or ''
            matched = next((pat for pat in PAYMENT_SCRIPT_HOST_PATTERNS if pat in host), None)
            if matched and host not in seen_hosts:
                seen_hosts.add(host)
                db.session.add(_make_finding(
                    db, Finding, scan_id=scan.id, asset_id=asset_id, severity='Low', cve='',
                    description=(
                        f"Third-party script executing in the browser on port {port}: {host} "
                        f"({src[:200]}). Special Note (§6.5): tag management/advertising/tracking "
                        f"scripts require business justification and secure implementation per "
                        f"PCI DSS Requirements 6.4.3 and 11.6.1."
                    ),
                    recommendation=(
                        "Confirm business need for this script, verify it is explicitly authorized, "
                        "and ensure it is loaded securely (integrity checking, restricted scope)."
                    ),
                    source_tool='payment-script-check', is_auto_fail=False
                ))
    if seen_hosts:
        db.session.commit()


def _check_load_balancer(scan_id, asset_id, hostname, db, Finding):
    """PCI §5.5 (Load Balancer Handling), localized-load-balancer half:
    'The ASV must obtain documented assurance from the customer that the
    infrastructure behind the load balancer is completely synchronized...
    If the customer cannot validate synchronization, the ASV must add a
    Special Note stating the customer is responsible for scanning the
    backend environment internally.'

    Detection: multiple DNS A records for one hostname is the standard
    signal of round-robin load balancing across backend servers -- this
    scan only ever reaches whichever single IP its own DNS resolution
    happens to return, so any OTHER backend behind the same hostname is
    invisible to it by construction.

    NOT implemented: §5.5's external/regional load-balancer half, which
    requires querying from multiple geographic vantage points to detect
    (a single-location scanner structurally can't observe that a
    different region gets routed to a different IP). Documented
    limitation, not a silent gap -- same honesty pattern as discovery.py's
    crawl-depth note.
    """
    if not hostname:
        return

    import discovery
    from models import Scan
    scan = Scan.query.get(scan_id)

    try:
        ips = discovery.resolve_all_a_records(hostname)
    except Exception as e:
        print(f"Load balancer check failed for {hostname}: {e}")
        return

    if len(ips) > 1:
        db.session.add(_make_finding(
            db, Finding, scan_id=scan.id, asset_id=asset_id, severity='Low', cve='',
            description=(
                f"Special Note (§5.5): {hostname} resolves to {len(ips)} distinct IP addresses "
                f"({', '.join(ips)}), indicating this hostname sits behind a load balancer. This "
                f"scan reaches only whichever backend its own DNS resolution returned -- other "
                f"backend(s) behind the same hostname were not directly scanned."
            ),
            recommendation=(
                "Provide documented assurance that all backend servers behind this load balancer "
                "are configuration-synchronized, or ensure each backend IP is scanned individually "
                "(e.g. as part of internal vulnerability scanning); per §5.5 this is the customer's "
                "responsibility if synchronization cannot be validated."
            ),
            source_tool='discovery', is_auto_fail=False
        ))
        db.session.commit()


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
                db.session.add(_make_finding(
                    db, Finding,
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
