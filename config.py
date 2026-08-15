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
