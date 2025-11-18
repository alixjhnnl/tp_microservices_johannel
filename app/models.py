from app import db
from datetime import datetime, timezone


class User(db.Model):
    """
    Modèle utilisateur basique :
    - id : identifiant interne
    - username : nom d'utilisateur (unique)
    - password_hash : mot de passe haché (jamais en clair)
    - created_at : date de création du compte
    """
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc)
    )

    def __repr__(self):
        return f"<User {self.username}>"

# -----------------------------------------------------------------
# Modèles pour préparer un vrai fournisseur OAuth2 (flask-oauthlib)
# -----------------------------------------------------------------

class OAuth2Client(db.Model):
    """
    Client OAuth2 (application qui consomme le service).
    "Auth Service / Client" dans l'archi.
    """
    __tablename__ = "oauth2_client"

    id = db.Column(db.Integer, primary_key=True)

    # Identifiants publics/privés côté client
    client_id = db.Column(db.String(40), unique=True, nullable=False)
    client_secret = db.Column(db.String(55), nullable=False)

    # utilisateur propriétaire du client (optionnel)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # Redirections et scopes
    _redirect_uris = db.Column("redirect_uris", db.Text)
    _default_scopes = db.Column("default_scopes", db.Text)

    def redirect_uris(self):
        return self._redirect_uris.split() if self._redirect_uris else []

    def default_scopes(self):
        return self._default_scopes.split() if self._default_scopes else []


class OAuth2Token(db.Model):
    """
    Token OAuth2 émis pour un client + un user.
    """
    __tablename__ = "oauth2_token"

    id = db.Column(db.Integer, primary_key=True)
    client_id = db.Column(db.String(40), db.ForeignKey("oauth2_client.client_id"))
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"))

    # Access / refresh token
    access_token = db.Column(db.String(255), unique=True)
    refresh_token = db.Column(db.String(255), unique=True)
    token_type = db.Column(db.String(40))

    # Expiration
    expires = db.Column(db.DateTime)

    # Scopes sous forme de chaînes
    scopes = db.Column(db.Text)

    def is_expired(self):
        if not self.expires:
            return True
        return self.expires < datetime.now(timezone.utc)
