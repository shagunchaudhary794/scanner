"""
Entrypoint for the Flask CLI (flask run, flask db migrate, flask db upgrade,
etc.) and for WSGI servers that want a plain `app` object (gunicorn wsgi:app).

app.py exposes create_app() as a factory rather than a module-level `app`
instance, so the CLI needs something to import. Set:

    export FLASK_APP=wsgi.py

before running `flask db ...` commands.
"""
from app import create_app

app = create_app()
