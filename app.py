import os
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from config import Config

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)
    migrate.init_app(app, db)

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

            # Ensure MVP local agents exist and are online
            internal_agent = Agent.query.filter_by(name='Local Celery Worker').first()
            if not internal_agent:
                internal_agent = Agent(name='Local Celery Worker', type='internal', status='online')
                db.session.add(internal_agent)
            else:
                internal_agent.status = 'online'

            external_agent = Agent.query.filter_by(name='Local OpenVAS').first()
            if not external_agent:
                external_agent = Agent(name='Local OpenVAS', type='external', status='online')
                db.session.add(external_agent)
            else:
                external_agent.status = 'online'

            db.session.commit()

    from routes import bp as main_bp
    app.register_blueprint(main_bp)

    # Register blueprints or routes here
    @app.route('/')
    def index():
        from models import Asset, Scan, Finding, Agent
        metrics = {
            'total_assets': Asset.query.count(),
            'active_scans': Scan.query.filter(Scan.status.in_(['queued', 'running'])).count(),
            'queued_scans': Scan.query.filter_by(status='queued').count(),
            'running_scans': Scan.query.filter_by(status='running').count(),
            'high_critical_findings': Finding.query.filter(Finding.severity.in_(['High', 'Critical'])).count(),
            'agents_online': Agent.query.filter_by(status='online').count(),
            'total_agents': Agent.query.count()
        }
        recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()
        recent_findings = Finding.query.order_by(Finding.created_at.desc()).limit(5).all()
        
        return render_template('index.html', metrics=metrics, recent_scans=recent_scans, recent_findings=recent_findings)

    return app

if __name__ == '__main__':
    app = create_app()
    app.run(debug=True)
