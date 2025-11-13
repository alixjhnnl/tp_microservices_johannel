from app import db
from datetime import datetime, timezone

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    auth_token = db.Column(db.String(512), nullable=True)
    token_expires_at = db.Column(db.DateTime, nullable=True)

    def __repr__(self):
        return f"<User {self.username}>"
