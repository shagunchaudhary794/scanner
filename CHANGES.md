# scanner-mvp — Session Changes

14 files changed, 540 insertions(+), 89 deletions(-)

## How to apply

Two options, pick one:

1. **Patch file** (`scanner-mvp-full.patch`): from the root of your local
   clone, run:
   ```
   git apply scanner-mvp-full.patch
   ```
2. **Full repo zip** (`scanner-mvp-updated.zip`): unzip and copy the files
   over your existing repo, or diff manually against what you have.

Either way, run this after applying to confirm nothing broke:
```
python3 -m py_compile tasks.py routes.py models.py app.py
bash -n dev.sh
```

---

## 1. OpenVAS connection bugs (`tasks.py`, `routes.py`)

- `_run_openvas_scan(scan, ...)` / `_run_nuclei_scan(scan, ...)` were
  passing the `Scan` ORM object where a `scan_id` was expected —
  `_run_openvas_scan` never rebound `scan` at all, guaranteeing a
  `NameError` on every external scan. Fixed: both call sites now pass
  `scan.id`.
- `_run_openvas_scan` imported `TLSConnection` but used
  `UnixSocketConnection` (never imported) — a second `NameError` hiding
  behind the first. Fixed.
- New `_get_gvm_connection()` helper in `tasks.py`: uses `TLSConnection`
  to `GVM_HOST:GVM_PORT` when `GVM_HOST` is set (host-run `./dev.sh`
  worker), otherwise `UnixSocketConnection` (full docker-compose, worker
  container shares the `gvmd_socket` volume). This is what `dev.sh` and
  the README already documented but the code never implemented.
- `routes.py`'s `cancel_scan` now uses the same helper instead of
  hardcoding the socket path — cancel actually reaches OpenVAS in dev
  mode now instead of silently no-op'ing.
- All four `test_openvas*.py` diagnostic scripts patched with the same
  `GVM_HOST`-aware connection logic for consistency.

## 2. New tool integrations (`tasks.py`, `Dockerfile`, compose files)

Per the PCI ASV reference doc, added the remaining tools (Masscan
excluded per your call):

- **Nmap + NSE** — `_run_nmap_scan()`, runs first on *every* scan
  (internal and external): full `-p-` TCP range, `-sV -O`, NSE
  `vuln,dns-zone-transfer` scripts. Feeds discovered ports downstream.
- **testssl.sh** — `_run_testssl_scan()`, external scans only, only runs
  if Nmap found a TLS port. Flags SSL/early-TLS as PCI auto-fail.
- **OWASP ZAP** — `_run_zap_scan()`, external scans only, only runs if
  Nmap found a web port. Runs as a persistent daemon
  (`docker-compose.yml`/`docker-compose.dev.yml` new `zap` service, port
  8090), driven over its plain JSON HTTP API. Flags SQLi/XSS/directory
  traversal/response-splitting as PCI auto-fail.
- Pipeline: **External** = Nmap → testssl (conditional) → ZAP
  (conditional) → Nuclei → OpenVAS. **Internal** = Nmap → OpenVAS →
  Nuclei (unchanged tool, now preceded by Nmap discovery).
- `Dockerfile`: added `nmap`, `dnsutils` apt packages; `testssl.sh`
  cloned from GitHub and symlinked to `/usr/local/bin/testssl.sh`.
- `requirements.txt`: unchanged — ZAP uses the existing `requests`
  dependency instead of adding the `zapv2` client library.

## 3. Dev-workflow hardening (`dev.sh`)

- `check_nmap_privileges()`: warns (non-fatal) if the host-run worker
  lacks `CAP_NET_RAW`/root, since `-O`/SYN-scan silently degrade without
  it. Suggests `sudo setcap cap_net_raw,cap_net_bind_service+eip`.
  Called from `cmd_worker()` and `cmd_dev()`.
- `cmd_test()` extended: now checks `nmap`/`testssl.sh`/`nuclei` are on
  PATH, pings ZAP's JSON API, and does a real connect/disconnect against
  OpenVAS via `_get_gvm_connection()` — previously only checked
  DB/Redis.
- `ZAP_HOST`/`ZAP_PORT` env vars added (default `localhost:8090`),
  `zap` added to the container list `cmd_up` starts.

## 4. Findings display gap (`models.py`, `routes.py`, templates)

- `models.py`: `Finding` gained `source_tool` and `is_auto_fail`
  columns — populated correctly by every tool in `tasks.py`, but nothing
  downstream was reading them.
- `routes.py`'s `generate_report()` CSV export now includes both
  columns.
- `templates/findings.html`, `templates/findings_pdf.html`,
  `templates/scan_detail.html`: added a "Tool" column and a red
  "Auto-Fail" badge next to the CVE whenever `is_auto_fail` is true —
  most visible in `findings_pdf.html` since that's the actual PCI-style
  report deliverable (auto-fail rows get a highlighted row background).

---

## Still open (not in this patch — see prior conversation for full list)

- CVSS v3.1 / NVD-backed unified scoring (`cvss_score`/`cvss_source`
  columns don't exist yet; severity is currently per-tool)
- Default-credential detection, unsupported-OS auto-fail
- DNS/MX/redirect scope-discovery validation (Phase 1, §4.4)
- Dispute/exception workflow (no `disputes` table)
- Proper 3-part PCI report structure (Attestation / Summary /
  Vulnerability Details) — current export is a flat findings list
- Compensating controls, 3-year retention fields on `Report`
