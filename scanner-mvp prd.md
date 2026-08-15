PRD
Product Requirements Document
Distributed Vulnerability Assessment Platform – MVP v1
1. Purpose
Build a simple distributed vulnerability assessment MVP that can run external and internal scans, store findings, and generate basic PCI-oriented reports. This MVP must follow the provided flow exactly and must avoid production-grade additions or extra compliance workflows not explicitly included in the current scope.


2. Product goal
The product should provide immediate operational value by allowing a user to:

Add assets.

Trigger internal or external scans.

Route scans through the correct scan path.

Collect vulnerability findings.

View scan status.

Generate reports in PDF and CSV.


3. Scope principles
This MVP must stay simple and in-scope:

No login/authentication in v1.

No RBAC in v1.

No dispute workflow.

No attestation/signature workflow.

No SIEM or ticketing integrations.

No AI prioritization.

No multi-tenancy.

No advanced production orchestration beyond what is needed to support the shown scan flow.

If any requirement is not present in the shared flow or current MVP scope, it should be treated as out of scope for this PRD.

Users
4. Primary users
This MVP serves these user roles at a functional level:

Security administrator, to add assets, deploy agents, and start scans.

Security analyst, to review findings.

Executive user, to view report summaries.

For v1, these roles do not require permission separation in the product because authentication and RBAC are intentionally excluded.

Product flow
5. Core workflow
The system must follow this exact flow:

User accesses the Flask application.

User creates or selects a scan.

User chooses scan type: external or internal.

If external, the scan manager sends the request to external OpenVAS.

If internal, the scan manager sends the request toward the internal network path.

Inside the internal network, the presence agent forwards or enables the request to the internal OpenVAS scanner.

The internal OpenVAS scanner scans internal assets.

Findings are returned to the control plane.

Findings are stored and shown in the dashboard.

Reports are generated from stored scan data.

6. Scan paths
6.1 External scan path
Triggered from Flask scan manager.

Executed by external OpenVAS.

Intended for internet-facing assets.

6.2 Internal scan path
Triggered from Flask scan manager.

Routed to internal network.

Requires presence agent.

Executed by internal OpenVAS scanner.

Intended for internal assets such as servers and endpoints.

Features
7. Included features
7.1 Flask control plane
The control plane must be an AWS-hosted Flask application responsible for:

Dashboard.

Asset inventory.

Scan creation.

Scan scheduling.

Report generation.

Agent management.

7.2 Dashboard
The dashboard should show:

Total assets.

Scan list.

Scan status.

Recent findings summary.

Reports list.

Agent presence status.

This should be simple and operational, not an advanced analytics dashboard.

7.3 Asset inventory
The system must allow adding and storing asset records. The minimum asset data model comes from the provided schema:

Asset ID.

Hostname.

IP Address.

Environment.

Criticality.

7.4 Scan management
The system must allow:

Creating a new scan.

Choosing scan type: internal or external.

Selecting target assets.

Viewing scan status.

Scheduling scans.

The minimum scan data model must include:

Scan ID.

Type.

Status.

Start Time.

End Time.

7.5 Agent management
The MVP must support:

Internal presence agent visibility.

External scanner agent presence as operational infrastructure.

Basic agent status display in dashboard.

For v1, agent management should remain minimal and focused on whether the internal path is available.

7.6 Internal scanner capability
Internal scanning must support:

Host discovery.

Port scanning.

Service enumeration.

Vulnerability scanning.

Technologies listed for internal agent:

Nmap.

OpenVAS / Greenbone.

Python plugins.

Docker.

Linux VM.

7.7 External scanner capability
External scanning must support:

Internet-facing vulnerability assessment.

TLS assessment.

DNS assessment.

Exposure monitoring.

The flow image shows external OpenVAS in the external path, so the MVP must keep that as the main external scan execution path.

7.8 Findings management
The system must store and display findings. The minimum findings schema is:

Asset.

Severity.

CVE.

Description.

Recommendation.

7.9 Reporting
The MVP must generate these reports:

Executive Summary.

Technical Findings.

Asset Inventory.

PCI-Oriented Assessment Report.

Supported formats:

PDF.

CSV.

Scan coverage
8. Minimum scan checks
The MVP should implement the checks listed in the provided scope and tool requirements.

8.1 Network discovery
Live host detection.

Open TCP ports.

Open UDP ports.

Service identification.

OS fingerprinting.

Primary tool:

Nmap.

8.2 Service exposure checks
Detect exposed:

FTP.

Telnet.

SSH.

SMTP.

DNS.

SNMP.

SMB.

RDP.

HTTP.

HTTPS.

8.3 TLS / SSL assessment
Detect:

SSLv2 enabled.

SSLv3 enabled.

Weak TLS configurations.

Expired certificates.

Self-signed certificates.

Weak ciphers.

Anonymous ciphers.

RC4 support.

3DES support.

Certificate hostname mismatch.

8.4 Web server security checks
Detect:

Missing HSTS.

Missing CSP.

Missing X-Frame-Options.

Missing X-Content-Type-Options.

Server version disclosure.

Directory listing exposure.

Default pages.

Weak cookie flags.

8.5 Authentication exposure checks
Detect:

Default credentials.

Anonymous access.

Guest access.

Weak administrative interfaces.

8.6 Remote administration exposure
Detect:

Public RDP.

Public SSH.

Public management portals.

Public hypervisor interfaces.

8.7 DNS security checks
Detect:

Zone transfer exposure.

Open recursion.

Information disclosure.

8.8 SMB security checks
Detect:

SMBv1 enabled.

Null sessions.

Signing disabled.

Known SMB vulnerabilities.

8.9 Database exposure checks
Detect:

Public databases.

Default configurations.

Version disclosure.

Supported databases:

MySQL.

PostgreSQL.

MSSQL.

MongoDB.

8.10 Vulnerability intelligence
OpenVAS findings must provide:

CVE mapping.

CVSS scores.

Severity ratings.

Severity levels:

Critical.

High.

Medium.

Low.

Informational.

Architecture
9. System architecture
9.1 Control plane
The control plane runs on AWS and includes:

Flask.

PostgreSQL.

Redis.

S3.

Responsibilities:

Scan orchestration.

Reporting.

Scheduling.

Asset management.

9.2 Scan plane
The scan plane includes:

Agent service.

Nmap engine.

OpenVAS engine.

Plugin engine.

9.3 Communication
Communication between control plane and scan plane is defined as:

HTTPS.

Mutual TLS.

10. Deployment model
10.1 External scanner deployment
External scanner agent deployed on AWS EC2.

10.2 Internal scanner deployment
Internal scanner agent deployed with Docker on Linux VM inside internal network.

Data model
11. MVP database entities
11.1 Assets
Fields:

Asset ID.

Hostname.

IP Address.

Environment.

Criticality.

11.2 Scans
Fields:

Scan ID.

Type.

Status.

Start Time.

End Time.

11.3 Findings
Fields:

Asset.

Severity.

CVE.

Description.

Recommendation.

12. Suggested minimal supporting entities
To support the defined flow without going out of scope, the MVP may also include:

Agents.

Reports.

Scan targets or scan-to-asset mapping.

These supporting entities are implementation helpers for the required features, not feature expansion.

Non-functional requirements
13. Targets
The MVP target values are:

10,000 assets.

100 concurrent scans.

50 agents.

99.5% availability.

14. Security for v1
The original scope mentions JWT authentication, RBAC, TLS encryption, mutual TLS, and audit logging.

For this PRD version:

Excluded for now: user login, JWT auth, RBAC.

Retained because part of architecture: HTTPS and mutual TLS for agent communication.

Optional later phase: audit logging UI and user-based authorization.

This keeps the product simple while preserving the scan-plane communication requirement.

Deliverables
15. MVP deliverables
Release 1
Flask control plane.

PostgreSQL.

Agent registration or presence tracking.

Release 2
Nmap integration.

Asset discovery.

Internal scanning.

Release 3
OpenVAS integration.

PCI-oriented checks.

Reporting.

Dashboard.

Out of scope
16. Explicitly out of scope for this MVP PRD
The following must not be included in this version:

Login and authentication UI.

RBAC and roles enforcement.

Multi-tenancy.

Compliance automation.

SIEM integrations.

Ticketing integrations.

Automated remediation.

AI risk prioritization.

Official PCI ASV certification workflow.

Dispute handling workflow.

Digital signatures and attestation workflow.

Advanced production-scale orchestration beyond the defined flow.

Success criteria
17. MVP success criteria
Within first deployment, success means:

Discover 95% or more reachable assets.

Successfully complete 95% of scheduled scans.

Generate reports in under 60 seconds.

Detect known CVEs identified by OpenVAS.

Produce PCI-oriented vulnerability assessment reports.

Acceptance criteria
18. Functional acceptance criteria
User can add assets manually into inventory.

User can create an internal scan.

User can create an external scan.

Internal scans route through the presence agent path.

External scans route to external OpenVAS.

Findings are saved and visible in dashboard.

Reports can be downloaded in PDF and CSV.

Dashboard shows scan status and agent presence.

Notes
19. Implementation note
This PRD intentionally removes login for now because you explicitly requested that it be deferred. The product should be built as a simple operational MVP first, following the exact shared flow and current written scope only.