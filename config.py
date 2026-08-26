import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Use environment variable for secret key in production
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-12345'
    
    # Require PostgreSQL for robust concurrent execution
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL', 'postgresql://scanner:scanner@db:5432/scanner')
    
    # Celery & Redis configuration
    CELERY_BROKER_URL = os.environ.get('CELERY_BROKER_URL', 'redis://redis:6379/0')
    CELERY_RESULT_BACKEND = os.environ.get('CELERY_RESULT_BACKEND', 'redis://redis:6379/0')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Session cookie hardening. SESSION_COOKIE_SECURE defaults to False
    # because local/dev deployments typically run over plain HTTP behind
    # no TLS terminator yet -- setting it True there means the session
    # cookie is silently never sent and login appears to "not work."
    # Set FORCE_SECURE_COOKIES=1 once real TLS is in front of this app.
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    SESSION_COOKIE_SECURE = os.environ.get('FORCE_SECURE_COOKIES', '0') == '1'
    PERMANENT_SESSION_LIFETIME = 60 * 60 * 8  # 8 hours

    # CSRF tokens (Flask-WTF) inherit SECRET_KEY automatically; no
    # separate WTF_CSRF_SECRET_KEY needed unless it should differ from
    # the session-signing key.

    # Dispute evidence storage (PCI reference doc §8: customer must supply
    # written, system-generated evidence -- screen captures, config files,
    # patch lists, etc. -- for false-positive/compensating-control claims).
    # Local disk for the MVP; production should point this at S3/MinIO the
    # same way the architecture doc's Report Storage Architecture (§44)
    # does for generated reports.
    EVIDENCE_UPLOAD_FOLDER = os.environ.get(
        'EVIDENCE_UPLOAD_FOLDER', os.path.join(basedir, 'evidence_uploads')
    )
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB cap on evidence uploads

    # Generated report storage (report_storage.py; §44 Report Storage
    # Architecture). Local disk for the MVP -- production should point
    # this at S3/MinIO the same way EVIDENCE_UPLOAD_FOLDER above should.
    REPORTS_STORAGE_FOLDER = os.environ.get(
        'REPORTS_STORAGE_FOLDER', os.path.join(basedir, 'generated_reports')
    )
