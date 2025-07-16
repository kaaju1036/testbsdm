import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key')

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        'SQLALCHEMY_DATABASE_URI',
        'mssql+pyodbc://ASTRODBADMIN:Fr12345678dom!@10.0.0.4/BSDMDB?driver=ODBC+Driver+17+for+SQL+Server'
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-Mail setup
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', 'support@orbiqetechnologies.com')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD', 'tcepksabkqhzxawb')

    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@orbiqe.com')
    ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin123#')  # Or better: use hashed password later



