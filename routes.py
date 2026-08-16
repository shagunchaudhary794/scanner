from flask import Blueprint, render_template, request, redirect, url_for, flash, make_response, send_file
import csv
import io
import pdfkit
from models import Asset, Scan, ScanTarget, Finding, Agent, Report
from app import db

from datetime import datetime

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
    report = Report(type=report_type, format=report_format, status='completed')
    db.session.add(report)
    db.session.commit()
    
    if report_format == 'csv':
        si = io.StringIO()
        cw = csv.writer(si)
        cw.writerow(['ID', 'Asset ID', 'Severity', 'CVE', 'CVSS Score', 'CVSS Source',
                     'Compliance Status', 'Source Tool', 'Auto-Fail', 'Description',
                     'Recommendation', 'Created At'])
        for f in findings:
            cw.writerow([
                f.id, f.asset_id, f.severity, f.cve,
                f.cvss_score if f.cvss_score is not None else '',
                f.cvss_source or '', f.compliance_status, f.source_tool,
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
