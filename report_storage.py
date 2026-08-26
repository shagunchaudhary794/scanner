"""
Report storage.

Architecture doc §44 (Report Storage Architecture): "Reports should not
be stored directly inside PostgreSQL. Instead: PostgreSQL stores
Metadata/Location/Retention Date; Object Storage stores PDF/CSV/Evidence
Files."

Every generated report was previously build-and-stream-only: the PDF/CSV
bytes existed for exactly as long as the HTTP response took to send, then
were gone. `Report.file_path` was a column nobody ever wrote to. This
module is the missing write path -- report bytes are saved here, and
`Report.file_path` records where, so a report can be re-downloaded later
exactly as it was generated (not regenerated, which could differ if a
finding's dispute status changed since).

Local disk for the MVP, same pattern as EVIDENCE_UPLOAD_FOLDER in
config.py. Swapping to S3/MinIO later only means changing save()/load()
below -- callers (routes.py) only ever deal with the stored filename
returned by save(), never a raw filesystem path, so the interface is
already storage-backend-agnostic.
"""

import os
import uuid


def _storage_dir():
    from flask import current_app
    return current_app.config['REPORTS_STORAGE_FOLDER']


def save(content_bytes, extension):
    """Persists report bytes and returns the stored filename (not a full
    path) -- same "store just the basename" pattern used for dispute/
    hosting evidence files, so the DB never leaks server filesystem
    layout and the same value works unchanged if storage later moves to
    S3 (an object key, not a local path).
    """
    storage_dir = _storage_dir()
    os.makedirs(storage_dir, exist_ok=True)
    filename = f"{uuid.uuid4().hex}.{extension}"
    with open(os.path.join(storage_dir, filename), 'wb') as f:
        f.write(content_bytes)
    return filename


def load(filename):
    """Returns the stored report's bytes, or None if it's missing (e.g.
    manually deleted from disk, or -- once a retention-cleanup job exists
    per §45/§49 -- purged after retention_until)."""
    if not filename:
        return None
    path = os.path.join(_storage_dir(), filename)
    if not os.path.exists(path):
        return None
    with open(path, 'rb') as f:
        return f.read()


def delete(filename):
    """Best-effort delete; used by a future retention-cleanup job (§45's
    'Archive OR Delete according to policy') -- not called anywhere yet,
    since this repo doesn't implement that job, only the field
    (Report.retention_until) it would read.
    """
    if not filename:
        return
    path = os.path.join(_storage_dir(), filename)
    try:
        os.remove(path)
    except OSError:
        pass
