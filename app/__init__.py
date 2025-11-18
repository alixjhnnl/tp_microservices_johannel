import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_oauthlib.provider import OAuth2Provider

# --------------------------------------------------------
# CREATION DE L'APP FLASK
# --------------------------------------------------------
app = Flask(__name__)

# --------------------------------------------------------
# CLE SECRETE POUR SESSIONS / COOKIES / OAuth2
# --------------------------------------------------------
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret')

# --------------------------------------------------------
# CONFIG DE LA BASE SQLITE
# --------------------------------------------------------
db_path = os.path.join(os.path.dirname(__file__), 'db.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{db_path}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# --------------------------------------------------------
# CONFIG OAUTH2 (durée de vie Tokens)
# --------------------------------------------------------
app.config['OAUTH2_PROVIDER_TOKEN_EXPIRES_IN'] = 3600  # 1 heure

# --------------------------------------------------------
# EXTENSIONS
# --------------------------------------------------------
db = SQLAlchemy(app)
oauth = OAuth2Provider(app)

# --------------------------------------------------------
# IMPORT DES MODELES ET DES VUES POUR EVITER IMPORTS CIRCULAIRES # noqa: E402,F401
# --------------------------------------------------------
from app import models, views  
