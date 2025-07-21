from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    otp = db.Column(db.String(6))
    otp_verified = db.Column(db.Boolean, default=False)
    attempted = db.Column(db.Boolean, default=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), db.ForeignKey('user.email'))
    score = db.Column(db.Integer)
    correct = db.Column(db.Integer, nullable=False)
    role = db.Column(db.String(50))
    timestamp = db.Column(db.DateTime, server_default=db.func.now())
