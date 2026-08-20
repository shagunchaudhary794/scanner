from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, send_file, current_app
import csv
import io
import os
import uuid
import pdfkit
from werkzeug.utils import secure_filename
from models import Asset, Scan, ScanTarget, Finding, Agent, Report, Dispute, OrgProfile
from app import db
import discovery
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

@bp.route('/assets')
def assets():
    all_assets = Asset.query.order_by(Asset.created_at.desc()).all()
    return render_template('assets.html', assets=all_assets)

@bp.route('/assets/new', methods=['GET', 'POST'])
def new_asset():
    if request.method == 'POST':
        hostname = request.form.get('hostname')
        ip_address = request.form.get('ip_address')
        environment = request.form.get('environment')
        criticality = request.form.get('criticality')
        
        asset = Asset(hostname=hostname, ip_address=ip_address, environment=environment, criticality=criticality)
        db.session.add(asset)
        db.session.commit()
        return redirect(url_for('main.assets'))
    return render_template('asset_form.html')


@bp.route('/assets/<int:id>')
def asset_detail(id):
    asset = Asset.query.get_or_404(id)
    asset_findings = Finding.query.filter_by(asset_id=id).order_by(Finding.created_at.desc()).all()
    return render_template('asset_detail.html', asset=asset, findings=asset_findings)


@bp.route('/assets/<int:id>/discover', methods=['POST'])
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
    if not asset.hostname:
        flash('Discovery requires a hostname (DNS-based checks need a domain, not just an IP).', 'error')
        return redirect(url_for('main.asset_detail', id=id))

    try:
        candidates = discovery.run_discovery(asset.hostname)
    except Exception as e:
        flash(f'Discovery failed: {e}', 'error')
        return redirect(url_for('main.asset_detail', id=id))

    # Don't re-suggest hosts that are already tracked as Assets.
    existing_hostnames = {a.hostname for a in Asset.query.all() if a.hostname}
    candidates = {h: v for h, v in candidates.items() if h not in existing_hostnames}

    return render_template('discovery_results.html', asset=asset, candidates=candidates)


@bp.route('/assets/<int:id>/discover/confirm', methods=['POST'])
def confirm_discovery(id):
    """Phase 1 Scoping: 'If the ASV finds hidden components not listed by
    the customer, they must consult the customer and record un-scanned
    items on the Attestation of Scan Compliance.' Only candidates the
    customer/analyst explicitly checked get added as real Assets.
    """
    source_asset = Asset.query.get_or_404(id)
    selected = request.form.getlist('confirm')  # each value: "hostname|ip|via"

    added = 0
    for entry in selected:
        try:
            hostname, ip, via = entry.split('|', 2)
        except ValueError:
            continue
        if Asset.query.filter_by(hostname=hostname).first():
            continue
        new = Asset(
            hostname=hostname,
            ip_address=ip or '0.0.0.0',
            environment=source_asset.environment,
            criticality=source_asset.criticality,
            discovered_via=via,
        )
        db.session.add(new)
        added += 1

    db.session.commit()
    flash(f'{added} discovered asset(s) added to scope.', 'success')
    return redirect(url_for('main.assets'))


@bp.route('/assets/<int:id>/scope', methods=['POST'])
def update_scope(id):
    """§4.2: an asset can only be marked out-of-scope with a formal
    segmentation attestation on record -- an empty attestation is refused
    outright rather than silently accepted, since §4.2's exact condition
    is that the customer 'must formally attest... adequate network
    segmentation.'
    """
    asset = Asset.query.get_or_404(id)
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
    flash('Scope updated.', 'success')
    return redirect(url_for('main.asset_detail', id=id))

@bp.route('/agents')
def agents():
    all_agents = Agent.query.order_by(Agent.last_seen.desc()).all()
    return render_template('agents.html', agents=all_agents)

@bp.route('/scans')
def scans():
    all_scans = Scan.query.order_by(Scan.created_at.desc()).all()
    return render_template('scans.html', scans=all_scans)

@bp.route('/scans/new', methods=['GET', 'POST'])
def new_scan():
    if request.method == 'POST':
        scan_type = request.form.get('type')
        asset_ids = request.form.getlist('asset_ids') # multiple selection
        
        if not asset_ids:
            # handle error, need at least one asset
            return redirect(url_for('main.new_scan'))
            
        scan = Scan(type=scan_type, status='queued')
        db.session.add(scan)
        db.session.flush() # get ID
        
        for asset_id in asset_ids:
            target = ScanTarget(scan_id=scan.id, asset_id=asset_id)
            db.session.add(target)
            
        db.session.commit()
        
        # Dispatch real background scan task via Celery
        from tasks import execute_scan
        task = execute_scan.delay(scan.id, scan_type, asset_ids)
        scan.celery_task_id = task.id
        db.session.commit()
        
        return redirect(url_for('main.scans'))
        
    all_assets = Asset.query.all()
    return render_template('scan_form.html', assets=all_assets)

@bp.route('/scans/<int:id>')
def scan_detail(id):
    scan = Scan.query.get_or_404(id)
    return render_template('scan_detail.html', scan=scan)

@bp.route('/scans/<int:id>/cancel', methods=['POST'])
def cancel_scan(id):
    scan = Scan.query.get_or_404(id)
    if scan.status in ['queued', 'running']:
        # Revoke celery task
        if scan.celery_task_id:
            from celery.app.control import Control
            from tasks import celery
            Control(celery).revoke(scan.celery_task_id, terminate=True, signal='SIGTERM')
            
        # Stop openvas task
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
        scan.progress = 'Scan cancelled by user.'
        scan.end_time = datetime.utcnow()
        db.session.commit()
        flash('Scan cancelled successfully.', 'info')
    else:
        flash('Scan cannot be cancelled in its current state.', 'error')
        
    return redirect(url_for('main.scan_detail', id=scan.id))

@bp.route('/findings')
def findings():
    all_findings = Finding.query.order_by(Finding.created_at.desc()).all()
    return render_template('findings.html', findings=all_findings)

@bp.route('/findings/<int:id>')
def finding_detail(id):
    finding = Finding.query.get_or_404(id)
    return render_template('finding_detail.html', finding=finding)

@bp.route('/findings/<int:id>/dispute', methods=['POST'])
def submit_dispute(id):
    """PCI reference doc §8: scan customer disputes a finding as either a
    false positive or via a compensating control, supplying written
    supporting evidence. This creates the dispute in 'pending' state --
    an ASV analyst must review it (see decide_dispute below); the ASV
    cannot auto-approve its own scan customer's claim.
    """
    finding = Finding.query.get_or_404(id)

    dispute_type = request.form.get('dispute_type')
    if dispute_type not in ('false_positive', 'compensating_control'):
        flash('Invalid dispute type.', 'error')
        return redirect(url_for('main.finding_detail', id=id))

    evidence_text = request.form.get('evidence_text', '').strip()
    submitted_by = request.form.get('submitted_by', '').strip()

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
        submitted_by=submitted_by or None,
        evidence_text=evidence_text,
        evidence_file_path=evidence_file_path,
        decision='pending',
    )
    db.session.add(dispute)
    db.session.commit()

    flash('Dispute submitted for ASV analyst review.', 'success')
    return redirect(url_for('main.finding_detail', id=id))


@bp.route('/disputes')
def disputes():
    """ASV analyst review queue. §8: 'Qualified ASV Employees must examine
    the customer's evidence for relevance and accuracy.' There's no
    auth/RBAC layer in this MVP yet -- once the control plane's JWT/RBAC
    work lands, this route should be restricted to the analyst role.
    """
    status_filter = request.args.get('status', 'pending')
    query = Dispute.query.order_by(Dispute.created_at.desc())
    if status_filter in ('pending', 'approved', 'rejected'):
        query = query.filter_by(decision=status_filter)
    all_disputes = query.all()
    return render_template('disputes.html', disputes=all_disputes, status_filter=status_filter)


@bp.route('/disputes/<int:id>/decision', methods=['POST'])
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
    dispute.reviewed_by = request.form.get('reviewed_by', '').strip() or None
    dispute.resolved_at = datetime.utcnow()
    db.session.commit()

    flash(f'Dispute #{dispute.id} marked {decision}.', 'success')
    return redirect(url_for('main.disputes'))


@bp.route('/settings/org', methods=['GET', 'POST'])
def org_settings():
    """§9.1: the Attestation of Scan Compliance cover sheet requires both
    Scan Customer Information and ASV Information (Company, Contact,
    Title, Phone, Email, Address, URL). Single-tenant MVP -- one row per
    role, edited here rather than through a full organizations table.
    """
    asv = OrgProfile.query.filter_by(role='asv').first()
    customer = OrgProfile.query.filter_by(role='customer').first()
    if not asv:
        asv = OrgProfile(role='asv')
        db.session.add(asv)
    if not customer:
        customer = OrgProfile(role='customer')
        db.session.add(customer)
    db.session.commit()

    if request.method == 'POST':
        for profile, prefix in ((asv, 'asv'), (customer, 'customer')):
            profile.company_name = request.form.get(f'{prefix}_company_name', '').strip()
            profile.contact_name = request.form.get(f'{prefix}_contact_name', '').strip()
            profile.title = request.form.get(f'{prefix}_title', '').strip()
            profile.phone = request.form.get(f'{prefix}_phone', '').strip()
            profile.email = request.form.get(f'{prefix}_email', '').strip()
            profile.address = request.form.get(f'{prefix}_address', '').strip()
            profile.url = request.form.get(f'{prefix}_url', '').strip()
        db.session.commit()
        flash('Organization profiles updated.', 'success')
        return redirect(url_for('main.org_settings'))

    return render_template('org_settings.html', asv=asv, customer=customer)


@bp.route('/evidence/<path:filename>')
def download_evidence(filename):
    """Serves an uploaded evidence file. filename is the stored (already
    UUID-prefixed) name, not user-controlled at request time."""
    upload_dir = current_app.config['EVIDENCE_UPLOAD_FOLDER']
    return send_file(os.path.join(upload_dir, filename))

@bp.route('/reports')
def reports():
    all_reports = Report.query.order_by(Report.created_at.desc()).all()
    completed_scans = Scan.query.filter_by(status='completed').order_by(Scan.created_at.desc()).all()
    return render_template('reports.html', reports=all_reports, completed_scans=completed_scans)

@bp.route('/reports/generate', methods=['POST'])
def generate_report():
    report_format = request.form.get('format', 'csv')
    scan_id = request.form.get('scan_id')
    
    query = Finding.query.order_by(Finding.created_at.desc())
    if scan_id:
        query = query.filter_by(scan_id=scan_id)
    findings = query.all()
    
    report_type = f'Scan {scan_id} Findings' if scan_id else 'Technical Findings'
    now = datetime.utcnow()
    report = Report(
        type=report_type, format=report_format, status='completed',
        created_at=now,
        # §10: 90-day attestation validity window
        expires_at=now + timedelta(days=90),
        # §10: 3-year ASV record-retention obligation
        retention_until=now + timedelta(days=365 * 3),
    )
    db.session.add(report)
    db.session.commit()

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
            
        output = make_response(si.getvalue())
        output.headers["Content-Disposition"] = f"attachment; filename=report_{report.id}.csv"
        output.headers["Content-type"] = "text/csv"
        return output
        
    elif report_format == 'pdf':
        html = render_template('findings_pdf.html', findings=findings)
        try:
            pdf = pdfkit.from_string(html, False)
            output = make_response(pdf)
            output.headers["Content-Disposition"] = f"attachment; filename=report_{report.id}.pdf"
            output.headers["Content-type"] = "application/pdf"
            return output
        except Exception as e:
            flash(f"PDF generation failed: {e}")
            return redirect(url_for('main.reports'))
            
    return redirect(url_for('main.reports'))


@bp.route('/reports/generate/full', methods=['POST'])
def generate_full_report():
    """Generates the complete three-part PCI report as one combined PDF,
    tied to a specific scan:
      - §9.1 Attestation of Scan Compliance (cover sheet + signatures)
      - §9.2 ASV Scan Report Summary (per-component pass/fail + correction plan)
      - §9.3 ASV Scan Vulnerability Details (full technical detail, CVSS, CVE, ports)

    This is how real ASV reports are typically delivered -- one document,
    three sections -- rather than three separate files.
    """
    scan_id = request.form.get('scan_id')
    if not scan_id:
        flash('A scan must be selected to generate a full PCI report.', 'error')
        return redirect(url_for('main.reports'))

    scan = Scan.query.get_or_404(scan_id)
    asv = OrgProfile.query.filter_by(role='asv').first()
    customer = OrgProfile.query.filter_by(role='customer').first()

    scan_targets = ScanTarget.query.filter_by(scan_id=scan.id).all()
    all_assets = [st.asset for st in scan_targets]
    in_scope_assets = [a for a in all_assets if not a.is_out_of_scope]
    excluded_assets = [a for a in all_assets if a.is_out_of_scope]

    findings = Finding.query.filter_by(scan_id=scan.id).all()
    findings.sort(key=lambda f: _SEVERITY_RANK.get(f.severity, 5))

    in_scope_asset_ids = {a.id for a in in_scope_assets}
    in_scope_findings = [f for f in findings if f.asset_id in in_scope_asset_ids]
    failing_findings = [f for f in in_scope_findings if f.effective_status == 'Fail']
    # §9.1: "A Pass only indicates whether the scanned systems are
    # compliant with... PCI DSS 11.3.2. It does not represent overall
    # compliance status with any other PCI DSS requirement."
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
        type=f'Full PCI Report - Scan {scan.id}', format='pdf', status='completed',
        report_type='full_pci', scan_id=scan.id, overall_result=overall_result,
        created_at=now,
        expires_at=now + timedelta(days=90),          # §10: 90-day attestation validity
        retention_until=now + timedelta(days=365 * 3), # §10: 3-year ASV record retention
    )
    db.session.add(report)
    db.session.commit()

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
        output = make_response(pdf)
        output.headers["Content-Disposition"] = f"attachment; filename=pci_report_scan_{scan.id}.pdf"
        output.headers["Content-type"] = "application/pdf"
        return output
    except Exception as e:
        report.status = 'failed'
        db.session.commit()
        flash(f"PDF generation failed: {e}", 'error')
        return redirect(url_for('main.reports'))

@bp.route('/api/agents/heartbeat', methods=['POST'])
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
