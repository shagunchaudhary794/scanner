from datetime import datetime, timedelta
from app import db
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

class Organization(db.Model):
    """A scan customer / tenant. PCI reference doc §9.1's 'Scan Customer
    Information' (Company, Contact, Title, Phone, Email, Address, URL)
    lives here now instead of on the old single-tenant OrgProfile. There
    is exactly one ASV (this platform) serving many Organizations -- see
    AsvProfile below, which is a single global row, not per-organization.
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    contact_name = db.Column(db.String(255), nullable=True)
    title = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    address = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    users = db.relationship('User', backref='organization', lazy=True)


class User(UserMixin, db.Model):
    """Two distinct kinds of account, distinguished by role and by
    whether organization_id is set:

    - Customer-side (organization_id NOT NULL): 'admin' | 'analyst' |
      'executive', scoped to exactly one Organization. Matches the
      architecture doc's Authorization Model -- admin manages
      users/scans/assets, analyst executes scans and submits disputes,
      executive is read-only.
    - ASV-side (organization_id IS NULL): 'asv_staff'. Works across every
      Organization. This is the only role allowed to decide disputes
      (§8: 'Qualified ASV Employees must examine the customer's
      evidence') or issue the final signed PCI report (§46.3:
      'Only an Authorized ASV Security Analyst... may issue the final
      PCI report'). A customer-side 'analyst' is NOT the same actor as
      an ASV analyst -- conflating them was the gap this fixes.
    """
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # admin | analyst | executive | asv_staff
    is_active_user = db.Column(db.Boolean, default=True)  # 'is_active' name is reserved by UserMixin
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login_at = db.Column(db.DateTime, nullable=True)
    # Login rate-limiting: no lockout protection existed on the
    # platform's OWN auth at all, which is a notable gap for a security
    # scanning product whose PCI checklist (§6.1) requires ITS scans to
    # detect exactly this kind of weakness in customer systems.
    failed_login_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    LOCKOUT_THRESHOLD = 5
    LOCKOUT_DURATION_MINUTES = 15

    @property
    def is_locked_out(self):
        return self.locked_until is not None and self.locked_until > datetime.utcnow()

    def register_failed_login(self):
        self.failed_login_attempts = (self.failed_login_attempts or 0) + 1
        if self.failed_login_attempts >= self.LOCKOUT_THRESHOLD:
            self.locked_until = datetime.utcnow() + timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)

    def register_successful_login(self):
        self.failed_login_attempts = 0
        self.locked_until = None
        self.last_login_at = datetime.utcnow()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    @property
    def is_active(self):
        # Overrides UserMixin.is_active (which just returns True) so a
        # deactivated account can't log in even with a valid password.
        return self.is_active_user

    @property
    def is_asv_staff(self):
        return self.role == 'asv_staff'

    def can_access_organization(self, organization_id):
        """ASV staff can see every tenant; customer-side users can only
        ever see their own. Every route that loads tenant data checks
        this rather than trusting the URL/form alone."""
        return self.is_asv_staff or self.organization_id == organization_id


class AuditLog(db.Model):
    """Architecture doc §47: 'All mutating routes must write to
    audit_logs.' organization_id is nullable because some actions (ASV
    staff editing the global AsvProfile, an ASV staff login) aren't
    scoped to a single tenant. user_id is nullable for the same reason
    plus system-initiated actions with no human actor.
    """
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(100), nullable=False)       # e.g. 'ASSET_CREATED', 'DISPUTE_APPROVED'
    entity_type = db.Column(db.String(50), nullable=True)    # e.g. 'Asset', 'Dispute'
    entity_id = db.Column(db.Integer, nullable=True)
    details = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class ScanJob(db.Model):
    """One asset's pipeline within a Scan. Orchestration engine doc §15/§17:
    a Scan decomposes into one ScanJob per asset, each progressing
    independently through Pending -> Running -> Completed/Failed ->
    Retry_Scheduled -> Aborted. The scheduler (tasks.py's scheduler_tick)
    is the only thing that moves a job out of 'pending' or
    'retry_scheduled' -- it does so by acquiring a Redis lock on the
    asset (lock_manager.py) before dispatching, so two jobs can never
    scan the same asset concurrently (§13 Distributed Lock Management).
    """
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')
    # pending | running | completed | failed | retry_scheduled | aborted
    attempt_number = db.Column(db.Integer, default=0)
    max_attempts = db.Column(db.Integer, default=5)  # matches §19's 5-attempt retry table
    assigned_agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=True)
    celery_task_id = db.Column(db.String(255), nullable=True)
    assigned_agent = db.relationship('Agent', foreign_keys=[assigned_agent_id])
    asset = db.relationship('Asset', foreign_keys=[asset_id])
    priority = db.Column(db.Integer, default=5)  # lower runs first; §36 "Critical Asset priority=1"
    # Scheduler-owned: when a failed job becomes eligible for another
    # dispatch attempt. NOT a Celery countdown -- see scheduler_tick's
    # docstring for why lock contention and execution failure use the
    # same requeue mechanism instead of self-rescheduling.
    next_retry_at = db.Column(db.DateTime, nullable=True)
    error_message = db.Column(db.Text, nullable=True)
    # PCI §6.8/§7/§14: an active protection system (WAF/IPS) blocking or
    # filtering the scan produces an "inconclusive scan," which must be
    # recorded as an automatic failure with the interference described --
    # NOT retried, since re-running Nmap against the same firewall won't
    # produce a different result. Set by _run_nmap_scan's filtered-port-
    # ratio heuristic; read by _recompute_scan_status for the Partial
    # label and surfaced via the auto-fail Finding it also creates.
    is_inconclusive = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)

    executions = db.relationship('JobExecution', backref='scan_job', lazy=True,
                                  order_by='JobExecution.attempt_number')


class JobExecution(db.Model):
    """Immutable per-attempt execution history (architecture doc §26.3:
    'Instead of Job Failed -> Update job row, the system stores Job +
    Execution Attempts'). ScanJob.status is the current state; this table
    is the append-only audit trail of every attempt that led there.
    """
    id = db.Column(db.Integer, primary_key=True)
    scan_job_id = db.Column(db.Integer, db.ForeignKey('scan_job.id'), nullable=False)
    agent_id = db.Column(db.Integer, db.ForeignKey('agent.id'), nullable=True)
    attempt_number = db.Column(db.Integer, nullable=False)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(50), nullable=True)  # running | success | failed
    error_message = db.Column(db.Text, nullable=True)


class ScanSchedule(db.Model):
    """PCI reference doc §10: 'External vulnerability scans must be
    performed at least once every three months.' §50 of the architecture
    doc: recurring scan schedules, checked periodically by
    tasks.check_scan_schedules and turned into a real Scan (+ ScanJobs
    for every currently in-scope asset) once due. Asset membership is
    NOT frozen at schedule-creation time -- each run scans whichever
    assets are in-scope for the organization *at that time*, since scope
    legitimately changes between quarters.
    """
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # 'internal' | 'external'
    frequency = db.Column(db.String(50), nullable=False)  # 'weekly' | 'monthly' | 'quarterly'
    next_run = db.Column(db.DateTime, nullable=False)
    last_run = db.Column(db.DateTime, nullable=True)
    enabled = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    hostname = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(50), nullable=False)
    environment = db.Column(db.String(50), nullable=True) # e.g., Production, Staging
    criticality = db.Column(db.String(50), nullable=True) # e.g., High, Medium, Low
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # How this asset entered scope. 'customer_provided' (default, manual
    # entry) vs. discovery-sourced values from discovery.py's `via` tags
    # ('dns_subdomain', 'mx_record', 'redirect'). PCI reference doc §4.4:
    # discovered components must be tracked distinctly from what the
    # customer originally supplied.
    discovered_via = db.Column(db.String(50), nullable=False, default='customer_provided')

    # §4.2: "System components can be excluded from the scan scope only
    # if... adequate physical or logical network segmentation must
    # completely isolate the excluded components from the CDE. The scan
    # customer must formally attest... that the specific component is out
    # of scope." segmentation_attestation is required text, not a
    # checkbox, so the attestation itself is on record -- an empty
    # attestation is treated as an invalid exclusion at the route layer.
    is_out_of_scope = db.Column(db.Boolean, default=False)
    segmentation_attestation = db.Column(db.Text, nullable=True)

    # §5.7/§14: "In a shared hosting or multi-tenant environment, the
    # customer could be compromised by weaknesses in another tenant's
    # setup." Only two valid resolutions: the provider supplies its own
    # independent passing ASV evidence, or the provider's infrastructure
    # is included in this scan. Mirrors the segmentation_attestation
    # pattern above -- a bare checkbox claiming "shared hosting, handled"
    # proves nothing, so evidence (file and/or written note) is required,
    # enforced the same way the empty-attestation exclusion is refused.
    is_shared_hosting = db.Column(db.Boolean, default=False)
    hosting_provider_name = db.Column(db.String(255), nullable=True)
    hosting_evidence_note = db.Column(db.Text, nullable=True)
    hosting_evidence_file_path = db.Column(db.String(255), nullable=True)

    # Relationships
    scan_targets = db.relationship('ScanTarget', backref='asset', lazy=True)
    findings = db.relationship('Finding', backref='asset', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
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
    scan_jobs = db.relationship('ScanJob', backref='scan', lazy=True)

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

    # Relationships
    disputes = db.relationship('Dispute', backref='finding', lazy=True,
                                order_by='Dispute.created_at.desc()')

    @property
    def compliance_status(self):
        """'Fail' if CVSS >= 4.0 or an explicit PCI auto-fail condition,
        else 'Pass' -- PCI reference doc §7. This is the RAW technical
        result, unaffected by disputes -- see effective_status for the
        dispute-adjusted outcome that actually belongs on a report."""
        if self.is_auto_fail:
            return 'Fail'
        if self.cvss_score is not None and self.cvss_score >= 4.0:
            return 'Fail'
        return 'Pass'

    @property
    def approved_dispute(self):
        """Most recent approved dispute against this finding, if any.
        A finding can accumulate multiple dispute attempts; only an
        approved one changes the reported outcome."""
        return next((d for d in self.disputes if d.decision == 'approved'), None)

    @property
    def effective_status(self):
        """PCI reference doc §7 (compensating controls) and §8 (dispute
        outcomes): a customer can pass a scan despite a Fail if the ASV
        approves a false-positive claim or a compensating control. The
        ASV can never delete the finding from the report (§8) -- only the
        reported compliance outcome changes. This is what belongs in the
        ASV Scan Report Summary's Compliance Status column (§9.2);
        compliance_status above is the pre-dispute technical result.
        """
        if self.approved_dispute:
            return 'Pass'
        return self.compliance_status

    @property
    def exception_note(self):
        """Text for the report's 'Exceptions, False Positives, or
        Compensating Controls' column (§9.2/§8) -- empty if there's no
        approved dispute."""
        d = self.approved_dispute
        if not d:
            return ''
        label = 'False Positive' if d.dispute_type == 'false_positive' else 'Compensating Control'
        return f"{label}: {d.decision_notes or 'Approved by ASV analyst.'}"


class Dispute(db.Model):
    """PCI reference doc §8 (Dispute Resolution Process) and §7
    (compensating controls). A dispute is the scan customer contesting a
    finding -- either claiming it's a false positive, or presenting a
    compensating control that reduces/eliminates the risk.

    Per §8: 'The ASV cannot simply delete disputes from the report; they
    must be explicitly documented... under Exceptions.' Note there is no
    RBAC/auth layer in this MVP yet (that's part of the control-plane
    work, not this repo) -- `reviewed_by` is a free-text field for now.
    Only an authorized ASV analyst should ever be the one calling the
    decision route once real auth exists.
    """
    id = db.Column(db.Integer, primary_key=True)
    finding_id = db.Column(db.Integer, db.ForeignKey('finding.id'), nullable=False)
    dispute_type = db.Column(db.String(50), nullable=False)  # 'false_positive' | 'compensating_control'
    submitted_by = db.Column(db.String(255), nullable=True)
    evidence_text = db.Column(db.Text, nullable=True)
    evidence_file_path = db.Column(db.String(255), nullable=True)
    reviewed_by = db.Column(db.String(255), nullable=True)
    decision = db.Column(db.String(50), default='pending')  # pending | approved | rejected
    decision_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    resolved_at = db.Column(db.DateTime, nullable=True)


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
    organization_id = db.Column(db.Integer, db.ForeignKey('organization.id'), nullable=False)
    type = db.Column(db.String(100), nullable=False) # Executive Summary, Technical Findings, etc.
    format = db.Column(db.String(20), nullable=False) # pdf, csv
    status = db.Column(db.String(50), default='generating') # generating, completed, failed
    file_path = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # PCI reference doc §10: "Report expiration period: 90 days from the
    # date the scan was completed" -- this is the Attestation's validity
    # window (§9.1's "Expiration date" field), distinct from retention.
    expires_at = db.Column(db.DateTime, nullable=True)
    # PCI reference doc §10: "3-year record retention rule... ASVs must
    # retain scan reports, related work papers, and work products for
    # three (3) years." A background job can later sweep
    # `retention_until < NOW()` per the architecture doc's Retention
    # Cleanup Job (§45/§49) -- not implemented here, just the field.
    retention_until = db.Column(db.DateTime, nullable=True)

    # §9: the full PCI report is three parts -- Attestation of Scan
    # Compliance (§9.1), ASV Scan Report Summary (§9.2), ASV Scan
    # Vulnerability Details (§9.3). report_type='full_pci' generates all
    # three as one combined document (how real ASV reports are typically
    # delivered); 'csv'-format exports remain the flat technical-findings
    # export from Phase 1/2a. scan_id ties a report to the specific scan
    # it's attesting to, needed for the Attestation's Pass/Fail + scan
    # date fields.
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=True)
    report_type = db.Column(db.String(50), nullable=True)  # 'full_pci' | 'technical_findings'
    # Computed at generation time: 'Pass' only if every in-scope finding's
    # effective_status is Pass (§9.1: "A Pass only indicates whether the
    # scanned systems are compliant with... PCI DSS 11.3.2").
    overall_result = db.Column(db.String(20), nullable=True)

    @property
    def is_expired(self):
        return self.expires_at is not None and datetime.utcnow() > self.expires_at


class AsvProfile(db.Model):
    """§9.1: the Attestation of Scan Compliance cover sheet requires ASV
    Information (Company, Contact, Title, Phone, Email, Address, URL).
    There is exactly one ASV -- this platform -- serving every
    Organization, so this is a single global row (id=1 by convention),
    not per-tenant. Formerly 'OrgProfile' with a role column
    distinguishing 'asv' vs 'customer' rows; customer info now lives on
    Organization since multi-tenancy means there are many customers, not
    one.
    """
    id = db.Column(db.Integer, primary_key=True)
    company_name = db.Column(db.String(255), nullable=True)
    contact_name = db.Column(db.String(255), nullable=True)
    title = db.Column(db.String(255), nullable=True)
    phone = db.Column(db.String(50), nullable=True)
    email = db.Column(db.String(255), nullable=True)
    address = db.Column(db.Text, nullable=True)
    url = db.Column(db.String(255), nullable=True)
