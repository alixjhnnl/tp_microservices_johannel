from flask import Flask
from flask_sqlalchemy import SQLAlchemy
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')

db_path = os.path.join(os.path.dirname(__file__), 'db.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# 1) Importer les modèles pour que SQLAlchemy connaisse User
from app import models  # <-- IMPORTANT : models avant create_all

# 2) Créer les tables au démarrage si elles n’existent pas
with app.app_context():
    db.create_all()
    print("✅ DB prête :", app.config['SQLALCHEMY_DATABASE_URI'])

# 3) Charger les routes
from app import views
