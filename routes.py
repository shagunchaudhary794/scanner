from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, send_file, current_app
import csv
import io
import os
import uuid
import pdfkit
from werkzeug.utils import secure_filename
from models import Asset, Scan, ScanTarget, Finding, Agent, Report, Dispute
from app import db

from datetime import datetime, timedelta

bp = Blueprint('main', __name__)

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


@bp.route('/evidence/<path:filename>')
def download_evidence(filename):
    """Serves an uploaded evidence file. filename is the stored (already
    UUID-prefixed) name, not user-controlled at request time."""
    upload_dir = current_app.config['EVIDENCE_UPLOAD_FOLDER']
    return send_file(os.path.join(upload_dir, filename))

@bp.route('/reports')
def reports():
    all_reports = Report.query.order_by(Report.created_at.desc()).all()
    return render_template('reports.html', reports=all_reports)

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
