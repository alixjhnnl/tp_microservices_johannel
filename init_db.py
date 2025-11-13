from app import app, db
from app.models import User

with app.app_context():
    print("🧱 Création des tables si nécessaire...")
    db.create_all()
    print("✅ Tables présentes :", [t.name for t in db.metadata.sorted_tables])
