from app import app, db
from app.models import User  # On importe juste pour que SQLAlchemy voie le modèle

with app.app_context():
    print("🔧 Drop des anciennes tables...")
    db.drop_all()

    print("🧱 Création des nouvelles tables...")
    db.create_all()

    print("✅ Tables créées :", [t.name for t in db.metadata.sorted_tables])
