# Scanner MVP

**Scanner MVP** is a distributed vulnerability assessment platform with a Flask-based control plane, designed for managing internal and external vulnerability scans, tracking findings, and generating PDF/CSV reports.

## Features

- **Dashboard:** A interface for high-density summary metrics (Assets, Active Scans, Findings, Agent Status).
- **Asset Inventory:** Manage target endpoints (IPs/Hostnames) for scanning.
- **Scan Scheduling:** Execute internal (via Presence Agent) and external scans asynchronously using Celery and Redis.
- **Findings Explorer:** Track vulnerabilities found, displaying severity and descriptions.
- **Reporting:** Export vulnerabilities into PDF (via `wkhtmltopdf`) and CSV formats.
- **Agent Management:** View deployed agents and their connection statuses.

## Architecture

1. **Flask (Web App):** The control plane and user interface.
2. **Celery Worker:** Handles asynchronous scan tasks and report generation.
3. **Redis:** Message broker and result backend for Celery.
4. **PostgreSQL:** Primary database to store assets, scans, findings, and agents.
5. **OpenVAS (Greenbone):** Vulnerability scanner container orchestration.

## Getting Started

The entire environment runs via Docker Compose.

### Prerequisites
- Docker & Docker Compose

### Quick Start
1. Clone this repository.
2. Run `docker compose up -d --build`.
3. Open your browser to `http://localhost:5000`.

### Database & Background Tasks
- Postgres runs locally on port `5432` internally.
- Redis handles the celery tasks in the background.

## Development

For faster iteration, the app and Celery worker run directly on the host with
hot-reload while Postgres, Redis and OpenVAS stay in Docker:

```bash
./dev.sh setup   # first time: venv + install deps
./dev.sh dev     # infra + background worker + Flask (hot-reload on :5000)
./dev.sh logs    # follow infra and worker logs (in another terminal)
```

Other commands: `./dev.sh web`, `./dev.sh worker`, `./dev.sh test`,
`./dev.sh stop`, `./dev.sh down`, `./dev.sh clean`. Run `./dev.sh help`
for details.

Notes:
- Dev infra ports (`5432`, `6379`, `9390`, `9392`) are exposed to the host via
  `docker-compose.dev.yml`.
- In dev the app connects to OpenVAS GMP at `localhost:9390`
  (`GVM_HOST=localhost`); inside Docker it still uses the `openvas` hostname.
- Connection settings are configurable via env: `DB_PORT`, `REDIS_PORT`,
  `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `GMP_HOST`.
