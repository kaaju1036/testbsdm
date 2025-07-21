from app import app
from extensions import db

with app.app_context():
    db.create_all()

# This exposes the `app` object for gunicorn (Render will look for `wsgi:app`)
application = app
