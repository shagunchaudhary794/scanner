from datetime import datetime
from app import db

class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=False)
    environment = db.Column(db.String(50), nullable=True) # e.g., Production, Staging
    criticality = db.Column(db.String(50), nullable=True) # e.g., High, Medium, Low
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scan_targets = db.relationship('ScanTarget', backref='asset', lazy=True)
    findings = db.relationship('Finding', backref='asset', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50), nullable=False) # 'internal' or 'external'
    status = db.Column(db.String(50), default='queued') # queued, running, completed, failed
    progress = db.Column(db.String(255), nullable=True)
    progress_percent = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text, nullable=True)
    celery_task_id = db.Column(db.String(255), nullable=True)
    openvas_task_id = db.Column(db.String(255), nullable=True)
    start_time = db.Column(db.DateTime, nullable=True)
    end_time = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scan_targets = db.relationship('ScanTarget', backref='scan', lazy=True)
    findings = db.relationship('Finding', backref='scan', lazy=True)

class ScanTarget(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)

class Finding(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    severity = db.Column(db.String(50), nullable=False) # Critical, High, Medium, Low, Informational
    cve = db.Column(db.String(100), nullable=True)
    description = db.Column(db.Text, nullable=True)
    recommendation = db.Column(db.Text, nullable=True)
    source_tool = db.Column(db.String(50), nullable=True)   # nmap, testssl, zap, nuclei, openvas
    is_auto_fail = db.Column(db.Boolean, default=False)     # PCI DSS automatic-fail condition (Req 11.3.2, §7)
    # NVD-backed CVSS v3.1 base score (see cvss_engine.py). Independent of
    # whatever severity label the source tool used -- this is what the
    # §7 "CVSS >= 4.0 = fail" rule and compliance_status below are computed
    # from, per the architecture doc's correction #4.
    cvss_score = db.Column(db.Float, nullable=True)
    # e.g. 'NVD-CVSSv3.1', 'NVD-CVSSv3.0', 'NVD-CVSSv2.0', 'tool-severity-fallback'
    cvss_source = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @property
    def compliance_status(self):
        """'Fail' if CVSS >= 4.0 or an explicit PCI auto-fail condition,
        else 'Pass' -- PCI reference doc §7. Feeds the ASV Scan Report
        Summary's per-vulnerability Compliance Status column (§9.2)."""
        if self.is_auto_fail:
            return 'Fail'
        if self.cvss_score is not None and self.cvss_score >= 4.0:
            return 'Fail'
        return 'Pass'


class CveCache(db.Model):
    """Postgres-backed cache of NVD lookups (DB is source of truth; Redis
    holds nothing durable). Keyed by CVE ID so repeat scans -- across
    assets, across quarters -- don't re-hit the NVD API for the same CVE.
    """
    cve_id = db.Column(db.String(30), primary_key=True)
    cvss_score = db.Column(db.Float, nullable=False)
    cvss_source = db.Column(db.String(50), nullable=False)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)

class Agent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    type = db.Column(db.String(50), nullable=False) # internal, external
    status = db.Column(db.String(50), default='offline') # online, offline
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100), nullable=False) # Executive Summary, Technical Findings, etc.
    format = db.Column(db.String(20), nullable=False) # pdf, csv
    status = db.Column(db.String(50), default='generating') # generating, completed, failed
    file_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
