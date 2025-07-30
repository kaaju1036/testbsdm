import os
from datetime import timedelta

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key')

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'DATABASE_URL',
        'sqlite:///' + os.path.join(basedir, 'data.db')
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-Mail setup
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'support@orbiqetechnologies.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'dribwsssscjxvryd')

    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@orbiqe.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123#')

    # 🔐 SESSION FIXES
    SESSION_COOKIE_SECURE = True       # Only send cookies via HTTPS
    SESSION_COOKIE_HTTPONLY = True     # Prevent JS access to cookies
    SESSION_COOKIE_SAMESITE = 'Lax'    # Cookie policy
    PERMANENT_SESSION_LIFETIME = timedelta(hours=1, minutes=20)
