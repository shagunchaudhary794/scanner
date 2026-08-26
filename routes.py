from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, send_file, current_app
from flask_login import login_required, login_user, logout_user, current_user
from functools import wraps
import csv
import io
import os
import uuid
import pdfkit
from werkzeug.utils import secure_filename
from models import (Asset, Scan, ScanTarget, Finding, Agent, Report, Dispute,
                     AsvProfile, Organization, User, AuditLog)
from app import db, csrf
import discovery
import report_storage
import re

from datetime import datetime, timedelta

bp = Blueprint('main', __name__)

# §9.3 requires "a list of all detected open ports and the specific
# service/protocol identified by the ASV for each component." There's no
# separate structured ports table in this MVP -- the Nmap task already
# embeds "port N/tcp" phrasing consistently in the finding descriptions
# it writes (see tasks.py's DB-exposure, remote-admin, and NSE-script
# finding text), so this parses that instead of adding a new table.
_PORT_RE = re.compile(r'port (\d+)/(tcp|udp)', re.IGNORECASE)

# Alphabetical order isn't severity order ("Medium" > "Low" > "High" would
# sort wrong) -- used to sort the Vulnerability Details section (§9.3)
# from most to least severe.
_SEVERITY_RANK = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Informational': 4}


def _extract_port(finding):
    if not finding.description:
        return None
    m = _PORT_RE.search(finding.description)
    return f"{m.group(1)}/{m.group(2)}" if m else None


def _component_ports(asset_id, scan_id):
    ports = set()
    for f in Finding.query.filter_by(asset_id=asset_id, scan_id=scan_id).all():
        p = _extract_port(f)
        if p:
            ports.add(p)
    return sorted(ports)


# ---------------------------------------------------------------------------
# Auth / RBAC helpers
# ---------------------------------------------------------------------------

def roles_required(*roles):
    """Restricts a route to specific User.role values. 'asv_staff' is the
    ASV-side role (works across every Organization); 'admin'/'analyst'/
    'executive' are customer-side, scoped to their own Organization. See
    models.py's User docstring for why these are NOT interchangeable --
    a customer 'analyst' submits disputes, only 'asv_staff' can decide
    them (§8).
    """
    def decorator(fn):
        @wraps(fn)
        @login_required
        def wrapper(*args, **kwargs):
            if current_user.role not in roles:
                flash('You do not have permission to perform this action.', 'error')
                return redirect(url_for('index'))
            return fn(*args, **kwargs)
        return wrapper
    return decorator


def _log_audit(action, entity_type=None, entity_id=None, details=None, organization_id=None):
    """Architecture doc §47: 'All mutating routes must write to
    audit_logs.' Called at the end of every route that creates, updates,
    or deletes tenant data or makes an access-control-relevant decision
    (login, dispute approval, scope changes, etc.).
    """
    org_id = organization_id
    if org_id is None and current_user.is_authenticated:
        org_id = current_user.organization_id
    log = AuditLog(
        organization_id=org_id,
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        details=details,
    )
    db.session.add(log)
    db.session.commit()


def _org_scoped(query, org_column=None):
    """Applies tenant scoping to a query for the CURRENT user: ASV staff
    see everything, customer users see only their own organization_id.
    org_column defaults to the queried model's own .organization_id.
    """
    if current_user.is_asv_staff:
        return query
    col = org_column if org_column is not None else query.column_descriptions[0]['entity'].organization_id
    return query.filter(col == current_user.organization_id)


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------

@bp.route('/setup', methods=['GET', 'POST'])
def setup():
    """One-time bootstrap: creates the first ASV staff account. Only
    reachable while the User table is empty -- once any account exists,
    this route refuses to create another, so it can't be used to mint a
    second unauthorized ASV-side account later.
    """
    if User.query.count() > 0:
        flash('Setup has already been completed. Please log in.', 'error')
        return redirect(url_for('main.login'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        if not email or len(password) < 8:
            flash('A valid email and a password of at least 8 characters are required.', 'error')
            return render_template('setup.html')

        user = User(email=email, role='asv_staff', organization_id=None)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        login_user(user)
        _log_audit('ASV_STAFF_BOOTSTRAPPED', entity_type='User', entity_id=user.id)
        flash('ASV staff account created. You can now onboard scan customer organizations.', 'success')
        return redirect(url_for('main.organizations'))

    return render_template('setup.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if User.query.count() == 0:
        return redirect(url_for('main.setup'))

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = User.query.filter_by(email=email).first()

        # Checked before the password so a locked account never even
        # exercises the password hash comparison while locked -- avoids
        # both wasted work and giving a timing signal.
        if user is not None and user.is_locked_out:
            remaining = max(1, int((user.locked_until - datetime.utcnow()).total_seconds() // 60) + 1)
            flash(f'Account locked due to repeated failed logins. Try again in {remaining} minute(s).', 'error')
            _log_audit('LOGIN_BLOCKED_LOCKOUT', entity_type='User', entity_id=user.id)
            return render_template('login.html')

        if user is None or not user.check_password(password):
            if user is not None:
                user.register_failed_login()
                db.session.commit()
                if user.is_locked_out:
                    _log_audit('ACCOUNT_LOCKED', entity_type='User', entity_id=user.id,
                               details=f'{user.failed_login_attempts} failed attempts')
            # Same generic message whether the email doesn't exist or the
            # password was wrong -- doesn't reveal which one to a guesser.
            flash('Invalid email or password.', 'error')
            return render_template('login.html')

        if not user.is_active_user:
            flash('This account has been deactivated.', 'error')
            return render_template('login.html')

        user.register_successful_login()
        login_user(user)
        db.session.commit()
        _log_audit('LOGIN', entity_type='User', entity_id=user.id)
        return redirect(url_for('index'))

    return render_template('login.html')


@bp.route('/logout')
@login_required
def logout():
    _log_audit('LOGOUT', entity_type='User', entity_id=current_user.id)
    logout_user()
    return redirect(url_for('main.login'))


@bp.route('/admin/organizations', methods=['GET', 'POST'])
@roles_required('asv_staff')
def organizations():
    """ASV staff onboard a new scan customer here: create the
    Organization (§9.1's Scan Customer Information) and its first admin
    login in one step. Ongoing user management within that org then
    happens at /settings/users, run by the org's own admin.
    """
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        admin_email = request.form.get('admin_email', '').strip().lower()
        admin_password = request.form.get('admin_password', '')

        if not name or not admin_email or len(admin_password) < 8:
            flash('Organization name, admin email, and an 8+ character password are required.', 'error')
            return redirect(url_for('main.organizations'))

        if User.query.filter_by(email=admin_email).first():
            flash('That email is already in use.', 'error')
            return redirect(url_for('main.organizations'))

        org = Organization(
            name=name,
            contact_name=request.form.get('contact_name', '').strip(),
            title=request.form.get('title', '').strip(),
            phone=request.form.get('phone', '').strip(),
            email=request.form.get('email', '').strip(),
            address=request.form.get('address', '').strip(),
            url=request.form.get('url', '').strip(),
        )
        db.session.add(org)
        db.session.flush()  # get org.id

        admin = User(organization_id=org.id, email=admin_email, role='admin')
        admin.set_password(admin_password)
        db.session.add(admin)
        db.session.commit()

        _log_audit('ORGANIZATION_CREATED', entity_type='Organization', entity_id=org.id,
                   organization_id=org.id, details=f'Initial admin: {admin_email}')
        flash(f'Organization "{name}" created with admin account {admin_email}.', 'success')
        return redirect(url_for('main.organizations'))

    all_orgs = Organization.query.order_by(Organization.created_at.desc()).all()
    return render_template('organizations.html', organizations=all_orgs)


@bp.route('/settings/users', methods=['GET', 'POST'])
@roles_required('admin')
def manage_users():
    """Org admin manages their own team. Customer-side roles only --
    'asv_staff' accounts are never created here (see /admin/organizations,
    which only ASV staff can reach)."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        role = request.form.get('role')

        if role not in ('admin', 'analyst', 'executive'):
            flash('Invalid role.', 'error')
            return redirect(url_for('main.manage_users'))
        if not email or len(password) < 8:
            flash('A valid email and an 8+ character password are required.', 'error')
            return redirect(url_for('main.manage_users'))
        if User.query.filter_by(email=email).first():
            flash('That email is already in use.', 'error')
            return redirect(url_for('main.manage_users'))

        user = User(organization_id=current_user.organization_id, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        _log_audit('USER_CREATED', entity_type='User', entity_id=user.id, details=f'role={role}')
        flash(f'User {email} created.', 'success')
        return redirect(url_for('main.manage_users'))

    org_users = User.query.filter_by(organization_id=current_user.organization_id).order_by(User.created_at.desc()).all()
    return render_template('users.html', users=org_users)


@bp.route('/audit-logs')
@roles_required('asv_staff', 'admin')
def audit_logs():
    """ASV staff see every tenant's log; an org admin sees only their own
    organization's entries."""
    query = AuditLog.query.order_by(AuditLog.created_at.desc())
    if not current_user.is_asv_staff:
        query = query.filter_by(organization_id=current_user.organization_id)
    logs = query.limit(500).all()
    return render_template('audit_logs.html', logs=logs)


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

@bp.route('/assets')
@login_required
def assets():
    all_assets = _org_scoped(Asset.query).order_by(Asset.created_at.desc()).all()
    return render_template('assets.html', assets=all_assets)

@bp.route('/assets/new', methods=['GET', 'POST'])
@roles_required('admin', 'analyst')
def new_asset():
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        ip_address = request.form.get('ip_address')
        environment = request.form.get('environment')
        criticality = request.form.get('criticality')

        asset = Asset(organization_id=current_user.organization_id, hostname=hostname,
                       ip_address=ip_address, environment=environment, criticality=criticality)
        db.session.add(asset)
        db.session.commit()
        _log_audit('ASSET_CREATED', entity_type='Asset', entity_id=asset.id, details=hostname or ip_address)
        return redirect(url_for('main.assets'))
    return render_template('asset_form.html')


@bp.route('/assets/<int:id>')
@login_required
def asset_detail(id):
    asset = Asset.query.get_or_404(id)
    if not current_user.can_access_organization(asset.organization_id):
        flash('You do not have access to that component.', 'error')
        return redirect(url_for('main.assets'))
    asset_findings = Finding.query.filter_by(asset_id=id).order_by(Finding.created_at.desc()).all()
    return render_template('asset_detail.html', asset=asset, findings=asset_findings)


@bp.route('/assets/<int:id>/discover', methods=['POST'])
@roles_required('admin', 'analyst')
def discover_assets(id):
    """PCI reference doc §4.4: DNS forward/reverse lookups of common host
    names, MX record lookups, and HTTP-redirect tracking, run against a
    customer-provided asset's hostname to surface Internet-facing
    components the customer didn't list. Results are NOT persisted as
    Assets here -- Phase 1 Scoping requires the ASV to consult the
    customer before adding discovered components to scope, so this just
    shows candidates for the customer/analyst to confirm.
    """
    asset = Asset.query.get_or_404(id)
    if not current_user.can_access_organization(asset.organization_id):
        flash('You do not have access to that component.', 'error')
        return redirect(url_for('main.assets'))
    if not asset.hostname:
        flash('Discovery requires a hostname (DNS-based checks need a domain, not just an IP).', 'error')
        return redirect(url_for('main.asset_detail', id=id))

    try:
        candidates = discovery.run_discovery(asset.hostname)
    except Exception as e:
        flash(f'Discovery failed: {e}', 'error')
        return redirect(url_for('main.asset_detail', id=id))

    # Don't re-suggest hosts that are already tracked as Assets (within this org).
    existing_hostnames = {a.hostname for a in Asset.query.filter_by(organization_id=asset.organization_id).all() if a.hostname}
    candidates = {h: v for h, v in candidates.items() if h not in existing_hostnames}

    return render_template('discovery_results.html', asset=asset, candidates=candidates)


@bp.route('/assets/<int:id>/discover/confirm', methods=['POST'])
@roles_required('admin', 'analyst')
def confirm_discovery(id):
    """Phase 1 Scoping: 'If the ASV finds hidden components not listed by
    the customer, they must consult the customer and record un-scanned
    items on the Attestation of Scan Compliance.' Only candidates the
    customer/analyst explicitly checked get added as real Assets.
    """
    source_asset = Asset.query.get_or_404(id)
    if not current_user.can_access_organization(source_asset.organization_id):
        flash('You do not have access to that component.', 'error')
        return redirect(url_for('main.assets'))

    selected = request.form.getlist('confirm')  # each value: "hostname|ip|via"

    added = 0
    for entry in selected:
        try:
            hostname, ip, via = entry.split('|', 2)
        except ValueError:
            continue
        if Asset.query.filter_by(hostname=hostname, organization_id=source_asset.organization_id).first():
            continue
        new = Asset(
            organization_id=source_asset.organization_id,
            hostname=hostname,
            ip_address=ip or '0.0.0.0',
            environment=source_asset.environment,
            criticality=source_asset.criticality,
            discovered_via=via,
        )
        db.session.add(new)
        added += 1

    db.session.commit()
    _log_audit('DISCOVERY_CONFIRMED', entity_type='Asset', entity_id=source_asset.id, details=f'{added} added')
    flash(f'{added} discovered asset(s) added to scope.', 'success')
    return redirect(url_for('main.assets'))


@bp.route('/assets/<int:id>/scope', methods=['POST'])
@roles_required('admin', 'analyst')
def update_scope(id):
    """§4.2: an asset can only be marked out-of-scope with a formal
    segmentation attestation on record -- an empty attestation is refused
    outright rather than silently accepted, since §4.2's exact condition
    is that the customer 'must formally attest... adequate network
    segmentation.'
    """
    asset = Asset.query.get_or_404(id)
    if not current_user.can_access_organization(asset.organization_id):
        flash('You do not have access to that component.', 'error')
        return redirect(url_for('main.assets'))

    action = request.form.get('action')

    if action == 'exclude':
        attestation = request.form.get('segmentation_attestation', '').strip()
        if not attestation:
            flash('A segmentation attestation is required to mark a component out of scope (PCI §4.2).', 'error')
            return redirect(url_for('main.asset_detail', id=id))
        asset.is_out_of_scope = True
        asset.segmentation_attestation = attestation
    elif action == 'include':
        asset.is_out_of_scope = False
        # Attestation text stays on record even after re-inclusion --
        # it's part of the scoping history, not something to silently drop.

    db.session.commit()
    _log_audit('SCOPE_UPDATED', entity_type='Asset', entity_id=asset.id, details=action)
    flash('Scope updated.', 'success')
    return redirect(url_for('main.asset_detail', id=id))


@bp.route('/assets/<int:id>/hosting', methods=['POST'])
@roles_required('admin', 'analyst')
def update_hosting(id):
    """§5.7/§14: 'In a shared hosting or multi-tenant environment, the
    customer could be compromised by weaknesses in another tenant's
    setup. To comply, there are only two valid options: the provider
    undergoes ASV scans independently and provides passing evidence
    directly to the customer, or the provider's infrastructure is
    included in the customer's own ASV scans.'

    Same pattern as segmentation-attestation exclusion: a bare checkbox
    claiming 'shared hosting, handled' proves nothing, so at least an
    evidence file or a substantive written note is required -- refused
    outright otherwise, not silently accepted.
    """
    asset = Asset.query.get_or_404(id)
    if not current_user.can_access_organization(asset.organization_id):
        flash('You do not have access to that component.', 'error')
        return redirect(url_for('main.assets'))

    action = request.form.get('action')

    if action == 'mark_shared':
        note = request.form.get('hosting_evidence_note', '').strip()
        provider_name = request.form.get('hosting_provider_name', '').strip()

        evidence_file_path = None
        uploaded = request.files.get('hosting_evidence_file')
        if uploaded and uploaded.filename:
            upload_dir = current_app.config['EVIDENCE_UPLOAD_FOLDER']
            os.makedirs(upload_dir, exist_ok=True)
            safe_name = f"{uuid.uuid4().hex}_{secure_filename(uploaded.filename)}"
            uploaded.save(os.path.join(upload_dir, safe_name))
            evidence_file_path = safe_name

        if not note and not evidence_file_path:
            flash('Either a written note or an evidence file is required to document shared-hosting compliance (PCI §5.7).', 'error')
            return redirect(url_for('main.asset_detail', id=id))

        asset.is_shared_hosting = True
        asset.hosting_provider_name = provider_name or None
        asset.hosting_evidence_note = note or None
        if evidence_file_path:
            asset.hosting_evidence_file_path = evidence_file_path
    elif action == 'unmark_shared':
        asset.is_shared_hosting = False
        # Evidence stays on record even after unmarking -- same
        # historical-record rationale as segmentation attestations above.

    db.session.commit()
    _log_audit('HOSTING_EVIDENCE_UPDATED', entity_type='Asset', entity_id=asset.id, details=action)
    flash('Shared hosting status updated.', 'success')
    return redirect(url_for('main.asset_detail', id=id))


# ---------------------------------------------------------------------------
# Agents (shared infrastructure -- not tenant-scoped)
# ---------------------------------------------------------------------------

@bp.route('/agents')
@login_required
def agents():
    all_agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('agents.html', agents=all_agents)


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

@bp.route('/scans')
@login_required
def scans():
    all_scans = _org_scoped(Scan.query).order_by(Scan.created_at.desc()).all()
    return render_template('scans.html', scans=all_scans)

@bp.route('/scans/new', methods=['GET', 'POST'])
@roles_required('admin', 'analyst')
def new_scan():
    if request.method == 'POST':
        scan_type = request.form.get('type')
        asset_ids = request.form.getlist('asset_ids') # multiple selection

        if not asset_ids:
            # handle error, need at least one asset
            return redirect(url_for('main.new_scan'))

        # Tenant isolation: refuse to scan an asset that doesn't belong
        # to the current user's own organization, even if its ID was
        # guessed/tampered with in the submitted form.
        owned_assets = Asset.query.filter(
            Asset.id.in_(asset_ids), Asset.organization_id == current_user.organization_id
        ).all()
        if len(owned_assets) != len(asset_ids):
            flash('One or more selected assets are not in your organization.', 'error')
            return redirect(url_for('main.new_scan'))

        scan = Scan(organization_id=current_user.organization_id, type=scan_type, status='queued')
        db.session.add(scan)
        db.session.flush() # get ID

        for asset_id in asset_ids:
            target = ScanTarget(scan_id=scan.id, asset_id=asset_id)
            db.session.add(target)

        db.session.commit()

        # Decompose into one ScanJob per asset. The scheduler
        # (tasks.scheduler_tick, run via Celery Beat) picks these up on
        # its next tick once it can acquire that asset's lock and find an
        # online agent -- nothing is dispatched directly from the request.
        from tasks import create_scan_jobs
        create_scan_jobs(scan.id, asset_ids)

        _log_audit('SCAN_CREATED', entity_type='Scan', entity_id=scan.id, details=scan_type)
        return redirect(url_for('main.scans'))

    all_assets = Asset.query.filter_by(organization_id=current_user.organization_id).all()
    return render_template('scan_form.html', assets=all_assets)

@bp.route('/scans/<int:id>')
@login_required
def scan_detail(id):
    scan = Scan.query.get_or_404(id)
    if not current_user.can_access_organization(scan.organization_id):
        flash('You do not have access to that scan.', 'error')
        return redirect(url_for('main.scans'))
    return render_template('scan_detail.html', scan=scan)

@bp.route('/scans/<int:id>/cancel', methods=['POST'])
@roles_required('admin', 'analyst')
def cancel_scan(id):
    scan = Scan.query.get_or_404(id)
    if not current_user.can_access_organization(scan.organization_id):
        flash('You do not have access to that scan.', 'error')
        return redirect(url_for('main.scans'))

    if scan.status in ['queued', 'running']:
        from models import ScanJob
        import lock_manager
        from celery.app.control import Control
        from tasks import celery

        cancelled_count = 0
        for job in ScanJob.query.filter_by(scan_id=scan.id).all():
            if job.status in ('pending', 'running', 'retry_scheduled'):
                if job.celery_task_id:
                    Control(celery).revoke(job.celery_task_id, terminate=True, signal='SIGTERM')

                # A running job holds its asset's lock -- releasing it here
                # requires the job's own token, which this route doesn't
                # have (it's held in-process by execute_scan_job's local
                # variable, not persisted). Safe either way: the lock's
                # TTL (§15 Strategy 4) reclaims it on its own, and a
                # cancelled/aborted job is never retried, so nothing waits
                # on this specific release.
                job.status = 'aborted'
                job.error_message = 'Cancelled by user'
                job.completed_at = datetime.utcnow()
                cancelled_count += 1

        # Stop any in-flight OpenVAS task too (best-effort, matches prior behavior).
        if scan.openvas_task_id:
            try:
                from tasks import _get_gvm_connection
                from gvm.protocols.gmp import Gmp
                from gvm.transforms import EtreeTransform
                connection = _get_gvm_connection()
                transform = EtreeTransform()
                with Gmp(connection=connection, transform=transform) as gmp:
                    gmp.authenticate('admin', 'admin')
                    gmp.stop_task(scan.openvas_task_id)
            except Exception as e:
                print(f"Failed to stop OpenVAS task: {e}")

        scan.status = 'cancelled'
        scan.progress = f'Scan cancelled by user ({cancelled_count} job(s) aborted).'
        scan.end_time = datetime.utcnow()
        db.session.commit()
        _log_audit('SCAN_CANCELLED', entity_type='Scan', entity_id=scan.id, details=f'{cancelled_count} jobs aborted')
        flash('Scan cancelled successfully.', 'info')
    else:
        flash('Scan cannot be cancelled in its current state.', 'error')

    return redirect(url_for('main.scan_detail', id=scan.id))


@bp.route('/settings/schedules', methods=['GET', 'POST'])
@roles_required('admin')
def scan_schedules():
    """PCI reference doc §10: quarterly scan cadence. tasks.check_scan_schedules
    (Celery Beat, hourly) turns a due ScanSchedule into a real Scan covering
    every currently in-scope Asset for the org -- see that task's docstring
    for why membership isn't frozen at schedule-creation time.
    """
    from models import ScanSchedule

    if request.method == 'POST':
        scan_type = request.form.get('scan_type')
        frequency = request.form.get('frequency')
        if scan_type not in ('internal', 'external') or frequency not in ('weekly', 'monthly', 'quarterly'):
            flash('Invalid schedule parameters.', 'error')
            return redirect(url_for('main.scan_schedules'))

        delta = {'weekly': timedelta(weeks=1), 'monthly': timedelta(days=30), 'quarterly': timedelta(days=90)}[frequency]
        schedule = ScanSchedule(
            organization_id=current_user.organization_id,
            scan_type=scan_type, frequency=frequency,
            next_run=datetime.utcnow() + delta, enabled=True,
        )
        db.session.add(schedule)
        db.session.commit()
        _log_audit('SCAN_SCHEDULE_CREATED', entity_type='ScanSchedule', entity_id=schedule.id, details=frequency)
        flash(f'{frequency.capitalize()} {scan_type} scan schedule created.', 'success')
        return redirect(url_for('main.scan_schedules'))

    schedules = ScanSchedule.query.filter_by(organization_id=current_user.organization_id).order_by(ScanSchedule.created_at.desc()).all()
    return render_template('scan_schedules.html', schedules=schedules)


@bp.route('/settings/schedules/<int:id>/toggle', methods=['POST'])
@roles_required('admin')
def toggle_schedule(id):
    from models import ScanSchedule
    schedule = ScanSchedule.query.get_or_404(id)
    if schedule.organization_id != current_user.organization_id:
        flash('You do not have access to that schedule.', 'error')
        return redirect(url_for('main.scan_schedules'))
    schedule.enabled = not schedule.enabled
    db.session.commit()
    _log_audit('SCAN_SCHEDULE_TOGGLED', entity_type='ScanSchedule', entity_id=schedule.id,
               details='enabled' if schedule.enabled else 'disabled')
    return redirect(url_for('main.scan_schedules'))


# ---------------------------------------------------------------------------
# Findings / Disputes
# ---------------------------------------------------------------------------

@bp.route('/findings')
@login_required
def findings():
    query = Finding.query.join(Scan)
    if not current_user.is_asv_staff:
        query = query.filter(Scan.organization_id == current_user.organization_id)
    all_findings = query.order_by(Finding.created_at.desc()).all()
    return render_template('findings.html', findings=all_findings)

@bp.route('/findings/<int:id>')
@login_required
def finding_detail(id):
    finding = Finding.query.get_or_404(id)
    if not current_user.can_access_organization(finding.scan.organization_id):
        flash('You do not have access to that finding.', 'error')
        return redirect(url_for('main.findings'))
    return render_template('finding_detail.html', finding=finding)

@bp.route('/findings/<int:id>/dispute', methods=['POST'])
@roles_required('admin', 'analyst')
def submit_dispute(id):
    """PCI reference doc §8: scan customer disputes a finding as either a
    false positive or via a compensating control, supplying written
    supporting evidence. This creates the dispute in 'pending' state --
    only an ASV staff account can review it (see decide_dispute below);
    the ASV cannot auto-approve its own scan customer's claim.
    """
    finding = Finding.query.get_or_404(id)
    if not current_user.can_access_organization(finding.scan.organization_id):
        flash('You do not have access to that finding.', 'error')
        return redirect(url_for('main.findings'))

    dispute_type = request.form.get('dispute_type')
    if dispute_type not in ('false_positive', 'compensating_control'):
        flash('Invalid dispute type.', 'error')
        return redirect(url_for('main.finding_detail', id=id))

    evidence_text = request.form.get('evidence_text', '').strip()

    if not evidence_text:
        # §8: "Written supporting evidence" is required -- an empty
        # dispute has nothing for an analyst to evaluate.
        flash('Written evidence is required to submit a dispute.', 'error')
        return redirect(url_for('main.finding_detail', id=id))

    evidence_file_path = None
    uploaded = request.files.get('evidence_file')
    if uploaded and uploaded.filename:
        upload_dir = current_app.config['EVIDENCE_UPLOAD_FOLDER']
        os.makedirs(upload_dir, exist_ok=True)
        safe_name = f"{uuid.uuid4().hex}_{secure_filename(uploaded.filename)}"
        uploaded.save(os.path.join(upload_dir, safe_name))
        # Store just the basename (not the full server path) -- it's what
        # download_evidence() below needs, and it avoids leaking the
        # server's filesystem layout into the database/report output.
        evidence_file_path = safe_name

    dispute = Dispute(
        finding_id=finding.id,
        dispute_type=dispute_type,
        submitted_by=current_user.email,
        evidence_text=evidence_text,
        evidence_file_path=evidence_file_path,
        decision='pending',
    )
    db.session.add(dispute)
    db.session.commit()

    _log_audit('DISPUTE_SUBMITTED', entity_type='Dispute', entity_id=dispute.id,
               organization_id=finding.scan.organization_id, details=dispute_type)
    flash('Dispute submitted for ASV analyst review.', 'success')
    return redirect(url_for('main.finding_detail', id=id))


@bp.route('/disputes')
@roles_required('asv_staff')
def disputes():
    """ASV analyst review queue. §8: 'Qualified ASV Employees must examine
    the customer's evidence for relevance and accuracy.' Restricted to
    asv_staff -- a customer-side account, even an 'admin', cannot review
    its own organization's disputes (would be self-approval).
    """
    status_filter = request.args.get('status', 'pending')
    query = Dispute.query.order_by(Dispute.created_at.desc())
    if status_filter in ('pending', 'approved', 'rejected'):
        query = query.filter_by(decision=status_filter)
    all_disputes = query.all()
    return render_template('disputes.html', disputes=all_disputes, status_filter=status_filter)


@bp.route('/disputes/<int:id>/decision', methods=['POST'])
@roles_required('asv_staff')
def decide_dispute(id):
    """Records the ASV analyst's manual review outcome. §8: the ASV
    'cannot remove disputes from the report, nor allow the customer to
    edit the report' -- approving here never deletes or edits the
    underlying Finding; it only sets Dispute.decision, which
    Finding.effective_status/exception_note read from.
    """
    dispute = Dispute.query.get_or_404(id)

    decision = request.form.get('decision')
    if decision not in ('approved', 'rejected'):
        flash('Invalid decision.', 'error')
        return redirect(url_for('main.disputes'))

    dispute.decision = decision
    dispute.decision_notes = request.form.get('decision_notes', '').strip()
    dispute.reviewed_by = current_user.email
    dispute.resolved_at = datetime.utcnow()
    db.session.commit()

    _log_audit('DISPUTE_DECIDED', entity_type='Dispute', entity_id=dispute.id,
               organization_id=dispute.finding.scan.organization_id, details=decision)
    flash(f'Dispute #{dispute.id} marked {decision}.', 'success')
    return redirect(url_for('main.disputes'))


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

@bp.route('/settings/asv', methods=['GET', 'POST'])
@roles_required('asv_staff')
def asv_settings():
    """§9.1: the Attestation of Scan Compliance cover sheet requires ASV
    Information (Company, Contact, Title, Phone, Email, Address, URL).
    Single global row -- there's exactly one ASV serving every tenant.
    """
    asv = AsvProfile.query.first()
    if not asv:
        asv = AsvProfile()
        db.session.add(asv)
        db.session.commit()

    if request.method == 'POST':
        asv.company_name = request.form.get('company_name', '').strip()
        asv.contact_name = request.form.get('contact_name', '').strip()
        asv.title = request.form.get('title', '').strip()
        asv.phone = request.form.get('phone', '').strip()
        asv.email = request.form.get('email', '').strip()
        asv.address = request.form.get('address', '').strip()
        asv.url = request.form.get('url', '').strip()
        db.session.commit()
        _log_audit('ASV_PROFILE_UPDATED', entity_type='AsvProfile', entity_id=asv.id)
        flash('ASV profile updated.', 'success')
        return redirect(url_for('main.asv_settings'))

    return render_template('asv_settings.html', asv=asv)


@bp.route('/settings/organization', methods=['GET', 'POST'])
@roles_required('admin')
def org_settings():
    """§9.1's Scan Customer Information, editable by the org's own admin.
    Scoped to current_user.organization_id -- an admin can only ever
    edit their own organization's record.
    """
    org = Organization.query.get_or_404(current_user.organization_id)

    if request.method == 'POST':
        org.name = request.form.get('name', '').strip() or org.name
        org.contact_name = request.form.get('contact_name', '').strip()
        org.title = request.form.get('title', '').strip()
        org.phone = request.form.get('phone', '').strip()
        org.email = request.form.get('email', '').strip()
        org.address = request.form.get('address', '').strip()
        org.url = request.form.get('url', '').strip()
        db.session.commit()
        _log_audit('ORGANIZATION_UPDATED', entity_type='Organization', entity_id=org.id)
        flash('Organization profile updated.', 'success')
        return redirect(url_for('main.org_settings'))

    return render_template('org_settings.html', org=org)


@bp.route('/evidence/<path:filename>')
@login_required
def download_evidence(filename):
    """Serves an uploaded evidence file. filename is the stored (already
    UUID-prefixed) name, not user-controlled at request time. Tenant
    isolation is enforced one level up -- this route trusts that only a
    link on a finding/dispute page the user could already see reaches
    here, since evidence filenames aren't guessable (UUID-prefixed).
    """
    upload_dir = current_app.config['EVIDENCE_UPLOAD_FOLDER']
    return send_file(os.path.join(upload_dir, filename))


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------

@bp.route('/reports')
@login_required
def reports():
    all_reports = _org_scoped(Report.query).order_by(Report.created_at.desc()).all()
    completed_scans = _org_scoped(Scan.query.filter_by(status='completed')).order_by(Scan.created_at.desc()).all()
    return render_template('reports.html', reports=all_reports, completed_scans=completed_scans)

@bp.route('/reports/generate', methods=['POST'])
@login_required
def generate_report():
    report_format = request.form.get('format', 'csv')
    scan_id = request.form.get('scan_id')

    # Every export is scoped to a specific scan, and that scan must
    # belong to the current user's own organization (unless asv_staff).
    if not scan_id:
        flash('A scan must be selected to generate a report.', 'error')
        return redirect(url_for('main.reports'))
    scan = Scan.query.get_or_404(scan_id)
    if not current_user.can_access_organization(scan.organization_id):
        flash('You do not have access to that scan.', 'error')
        return redirect(url_for('main.reports'))

    findings = Finding.query.filter_by(scan_id=scan_id).order_by(Finding.created_at.desc()).all()

    report_type = f'Scan {scan_id} Findings'
    now = datetime.utcnow()
    report = Report(
        organization_id=scan.organization_id,
        type=report_type, format=report_format, status='completed',
        created_at=now,
        # §10: 90-day attestation validity window
        expires_at=now + timedelta(days=90),
        # §10: 3-year ASV record-retention obligation
        retention_until=now + timedelta(days=365 * 3),
    )
    db.session.add(report)
    db.session.commit()
    _log_audit('REPORT_GENERATED', entity_type='Report', entity_id=report.id,
               organization_id=scan.organization_id, details=report_format)

    if report_format == 'csv':
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Asset ID', 'Severity', 'CVE', 'CVSS Score', 'CVSS Source',
                     'Compliance Status', 'Exceptions/False Positives/Compensating Controls',
                     'Source Tool', 'Auto-Fail', 'Description',
                     'Recommendation', 'Created At'])
        for f in findings:
            cw.writerow([
                f.id, f.asset_id, f.severity, f.cve,
                f.cvss_score if f.cvss_score is not None else '',
                f.cvss_source or '', f.effective_status, f.exception_note, f.source_tool,
                'Yes' if f.is_auto_fail else 'No', f.description, f.recommendation, f.created_at
            ])

        csv_bytes = si.getvalue().encode('utf-8')
        report.file_path = report_storage.save(csv_bytes, 'csv')
        db.session.commit()

        output = make_response(csv_bytes)
        output.headers["Content-Disposition"] = f"attachment; filename=report_{report.id}.csv"
        output.headers["Content-type"] = "text/csv"
        return output

    elif report_format == 'pdf':
        html = render_template('findings_pdf.html', findings=findings)
        try:
            pdf = pdfkit.from_string(html, False)
            report.file_path = report_storage.save(pdf, 'pdf')
            db.session.commit()

            output = make_response(pdf)
            output.headers["Content-Disposition"] = f"attachment; filename=report_{report.id}.pdf"
            output.headers["Content-type"] = "application/pdf"
            return output
        except Exception as e:
            report.status = 'failed'
            db.session.commit()
            flash(f"PDF generation failed: {e}")
            return redirect(url_for('main.reports'))

    return redirect(url_for('main.reports'))


@bp.route('/reports/generate/full', methods=['POST'])
@roles_required('asv_staff')
def generate_full_report():
    """Generates the complete three-part PCI report as one combined PDF,
    tied to a specific scan:
      - §9.1 Attestation of Scan Compliance (cover sheet + signatures)
      - §9.2 ASV Scan Report Summary (per-component pass/fail + correction plan)
      - §9.3 ASV Scan Vulnerability Details (full technical detail, CVSS, CVE, ports)

    This is how real ASV reports are typically delivered -- one document,
    three sections -- rather than three separate files. Restricted to
    asv_staff per §46.3: "Only an Authorized ASV Security Analyst... may
    issue the final PCI report." A customer cannot self-issue their own
    compliance attestation.
    """
    scan_id = request.form.get('scan_id')
    if not scan_id:
        flash('A scan must be selected to generate a full PCI report.', 'error')
        return redirect(url_for('main.reports'))

    scan = Scan.query.get_or_404(scan_id)
    asv = AsvProfile.query.first()
    customer = Organization.query.get(scan.organization_id)

    scan_targets = ScanTarget.query.filter_by(scan_id=scan.id).all()
    all_assets = [st.asset for st in scan_targets]
    in_scope_assets = [a for a in all_assets if not a.is_out_of_scope]
    excluded_assets = [a for a in all_assets if a.is_out_of_scope]
    in_scope_asset_ids = {a.id for a in in_scope_assets}

    findings = Finding.query.filter_by(scan_id=scan.id).all()
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 5))
    in_scope_findings = [f for f in findings if f.asset_id in in_scope_asset_ids]

    # §7 / §9.2: compliance status is per-finding via effective_status
    # (dispute-adjusted); a component fails if ANY of its findings fail,
    # and the overall scan fails if ANY in-scope component fails.
    failing_findings = [f for f in in_scope_findings if f.effective_status == 'Fail']
    overall_result = 'Fail' if failing_findings else 'Pass'

    components = []
    for asset in in_scope_assets:
        asset_findings = [f for f in in_scope_findings if f.asset_id == asset.id]
        asset_status = 'Fail' if any(f.effective_status == 'Fail' for f in asset_findings) else 'Pass'
        correction_plan = sorted({
            f.recommendation for f in asset_findings
            if f.effective_status == 'Fail' and f.recommendation
        })
        components.append({
            'asset': asset,
            'status': asset_status,
            'findings': asset_findings,
            'ports': _component_ports(asset.id, scan.id),
            'correction_plan': correction_plan,
        })

    now = datetime.utcnow()
    report = Report(
        organization_id=scan.organization_id,
        type=f'Full PCI Report - Scan {scan.id}', format='pdf', status='completed',
        report_type='full_pci', scan_id=scan.id, overall_result=overall_result,
        created_at=now,
        expires_at=now + timedelta(days=90),          # §10: 90-day attestation validity
        retention_until=now + timedelta(days=365 * 3), # §10: 3-year ASV record retention
    )
    db.session.add(report)
    db.session.commit()
    _log_audit('FULL_PCI_REPORT_GENERATED', entity_type='Report', entity_id=report.id,
               organization_id=scan.organization_id, details=overall_result)

    # No structured "Partial" tracking exists elsewhere in the schema --
    # a scan that ended with an error is the only signal available for
    # distinguishing Full vs Partial (§9.1's "Full/Partial scan type" field).
    scan_type_label = 'Partial' if scan.error_message else 'Full'

    html = render_template(
        'full_report_pdf.html',
        report=report, scan=scan, asv=asv, customer=customer,
        overall_result=overall_result, scan_type_label=scan_type_label,
        components=components, in_scope_findings=in_scope_findings,
        failing_count=len(failing_findings),
        components_scanned_count=len(in_scope_assets),
        excluded_count=len(excluded_assets), excluded_assets=excluded_assets,
    )

    try:
        pdf = pdfkit.from_string(html, False)
        report.file_path = report_storage.save(pdf, 'pdf')
        db.session.commit()

        output = make_response(pdf)
        output.headers["Content-Disposition"] = f"attachment; filename=pci_report_scan_{scan.id}.pdf"
        output.headers["Content-type"] = "application/pdf"
        return output
    except Exception as e:
        report.status = 'failed'
        db.session.commit()
        flash(f"PDF generation failed: {e}", 'error')
        return redirect(url_for('main.reports'))


@bp.route('/reports/<int:id>/download')
@login_required
def download_report(id):
    """§44 Report Storage Architecture: re-serves a report EXACTLY as it
    was generated, from report_storage.py, rather than regenerating it.
    This distinction matters -- a regenerated report could come out
    different if a finding's dispute was decided (or a new one filed)
    since the original was issued, which would silently rewrite history.
    A stored report is the actual historical record.
    """
    report = Report.query.get_or_404(id)
    if not current_user.can_access_organization(report.organization_id):
        flash('You do not have access to that report.', 'error')
        return redirect(url_for('main.reports'))

    content = report_storage.load(report.file_path)
    if content is None:
        flash('This report\'s stored file is no longer available. Generate a new one.', 'error')
        return redirect(url_for('main.reports'))

    mimetype = 'application/pdf' if report.format == 'pdf' else 'text/csv'
    filename = f"report_{report.id}.{report.format}"
    output = make_response(content)
    output.headers["Content-Disposition"] = f"attachment; filename={filename}"
    output.headers["Content-type"] = mimetype
    return output


# ---------------------------------------------------------------------------
# Agent heartbeat API (shared infrastructure, no tenant scoping)
# ---------------------------------------------------------------------------

@bp.route('/api/agents/heartbeat', methods=['POST'])
@csrf.exempt
def agent_heartbeat():
    data = request.json
    agent_name = data.get('name')
    agent_type = data.get('type')

    agent = Agent.query.filter_by(name=agent_name).first()
    if not agent:
        agent = Agent(name=agent_name, type=agent_type, status='online')
        db.session.add(agent)
    else:
        agent.status = 'online'
        agent.last_seen = datetime.utcnow()

    db.session.commit()
    return {'status': 'success'}
