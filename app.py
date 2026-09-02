import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_login import LoginManager, current_user
from flask_wtf import CSRFProtect
from config import Config

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
login_manager = LoginManager()
csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message = 'Please log in to continue.'
    login_manager.login_message_category = 'error'

    @login_manager.user_loader
    def load_user(user_id):
        from models import User
        return User.query.get(int(user_id))

    with app.app_context():
        import models  # noqa: F401 -- registers models on db.metadata

        # FLASK_RUN_FROM_CLI is set by Flask itself whenever the app is
        # loaded through the `flask` command (flask db migrate/upgrade/
        # init, flask shell, etc.). We skip the auto-create/seed step in
        # that case so Alembic sees the database's true current state
        # instead of a DB that create_all() just silently brought up to
        # date behind its back -- otherwise `flask db migrate` would
        # generate an empty diff even when a real migration is needed.
        #
        # Outside the CLI (docker-compose / gunicorn / `python app.py`),
        # this still runs as before for local/dev convenience. Schema
        # changes going forward should ship as Alembic migrations
        # (`flask db upgrade`) rather than relying on create_all() to
        # patch existing databases -- create_all() only creates tables
        # that don't exist yet, it never alters existing ones.
        if not os.environ.get('FLASK_RUN_FROM_CLI'):
            from models import Agent
            db.create_all()

            # Ensure MVP local agents exist. Status is only set at
            # CREATION time -- not on every call. This function runs
            # inside every Celery task's own create_app() (scheduler_tick
            # alone fires every 5s via Beat), so unconditionally forcing
            # status='online' here would silently undo
            # check_agent_heartbeats' stale-detection (and any future
            # manual "mark offline" action) within one tick. Ongoing
            # status belongs to /api/agents/heartbeat and
            # check_agent_heartbeats, not to app boot.
            internal_agent = Agent.query.filter_by(name='Local Celery Worker').first()
            if not internal_agent:
                internal_agent = Agent(name='Local Celery Worker', type='internal', status='online')
                db.session.add(internal_agent)

            external_agent = Agent.query.filter_by(name='Local OpenVAS').first()
            if not external_agent:
                external_agent = Agent(name='Local OpenVAS', type='external', status='online')
                db.session.add(external_agent)

            db.session.commit()

    from routes import bp as main_bp
    app.register_blueprint(main_bp)

    # Register blueprints or routes here
    @app.route('/')
    def index():
        from flask_login import login_required
        if not current_user.is_authenticated:
            from flask import redirect, url_for
            return redirect(url_for('main.login'))

        from models import Asset, Scan, Finding, Agent

        # Tenant scoping: ASV staff see platform-wide totals; a customer
        # user only ever sees their own organization's numbers.
        if current_user.is_asv_staff:
            asset_q = Asset.query
            scan_q = Scan.query
            finding_q = Finding.query
        else:
            asset_q = Asset.query.filter_by(organization_id=current_user.organization_id)
            scan_q = Scan.query.filter_by(organization_id=current_user.organization_id)
            finding_q = Finding.query.join(Scan).filter(Scan.organization_id == current_user.organization_id)

        metrics = {
            'total_assets': asset_q.count(),
            'active_scans': scan_q.filter(Scan.status.in_(['queued', 'running'])).count(),
            'queued_scans': scan_q.filter_by(status='queued').count(),
            'running_scans': scan_q.filter_by(status='running').count(),
            'high_critical_findings': finding_q.filter(Finding.severity.in_(['High', 'Critical'])).count(),
            'agents_online': Agent.query.filter_by(status='online').count(),
            'total_agents': Agent.query.count()
        }
        recent_scans = scan_q.order_by(Scan.created_at.desc()).limit(5).all()
        recent_findings = finding_q.order_by(Finding.created_at.desc()).limit(5).all()

        return render_template('index.html', metrics=metrics, recent_scans=recent_scans, recent_findings=recent_findings)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
