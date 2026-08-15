from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from config import Config

# Initialize extensions
db = SQLAlchemy()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize Flask extensions here
    db.init_app(app)

    with app.app_context():
        import models
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
