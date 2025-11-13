import os, json, jwt
from flask import render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import User
from app import app, db
from datetime import datetime, timezone, timedelta
from functools import wraps

# --- Config JWT ---
JWT_SECRET = app.config['SECRET_KEY']       
JWT_ALGO = "HS256"
JWT_EXP_MINUTES = 1 

"""Création JWT pour utilisateur"""
 
def create_jwt(username: str) -> str:  
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp())
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return token if isinstance(token, str) else token.decode("utf-8")

def verify_jwt(token: str):
    """Vérifie un JWT + cohérence avec la base. Renvoie le payload ou None."""
    try:
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    username = payload.get("sub")
    if not username:
        return None

    user = User.query.filter_by(username=username).first()
    if user is None:
        return None

    # le token stocké ne correspond pas → invalide
    if user.auth_token != token:
        return None

    # date d'expiration en base
    if not user.token_expires_at or user.token_expires_at < datetime.now(timezone.utc):
        return None

    return payload
    
# --- transport token ---
def jwt_required(f):
    """vérifie qu'un JWT valide est présent avant d'accéder à la route."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        token = session.get("jwt_token")
        if not token:
            flash("Tu dois être connecté pour accéder à cette ressource.", "err")
            return redirect(url_for("index"))

        payload = verify_jwt(token)
        if payload is None:
            flash("Session expirée ou invalide. Reconnecte-toi.", "err")
            # on nettoie le token invalide
            session.pop("jwt_token", None)
            return redirect(url_for("index"))

        # on peut récupérer le username depuis payload["sub"] si besoin
        return f(*args, **kwargs)
    return wrapper

# --- LOG user ---
def log_user_login(user_id: str):
    data_dir = os.path.join(app.root_path, "data")
    os.makedirs(data_dir, exist_ok=True)
    log_path = os.path.join(data_dir, "logins.json")

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            entries = json.load(f)
            if not isinstance(entries, list):
                entries = []
    except FileNotFoundError:
        entries = []

    entries.append({
        "user": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
        
# ---------- routes ----------
@app.route("/")
def index():
    return render_template("index.html")

# Inscription (optionnelle)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('nom')
        password = request.form.get('mdp')
        if not username or not password:
            flash("Remplis nom et mot de passe", "err")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash("Nom d'utilisateur déjà pris", "err")
            return redirect(url_for('register'))

        hash_pw = generate_password_hash(password)
        user = User(username=username, password_hash=hash_pw)
        db.session.add(user)
        db.session.commit()
        flash("Compte créé — tu peux te connecter.", "ok")
        return redirect(url_for('index'))

    return render_template('register.html')  # crée ce template si tu veux l’inscription via UI

# Connexion stricte (pas d’auto-création)
@app.route("/api/utilisateurs", methods=["POST"])
def ajouter_utilisateur():
    username = request.form.get("nom")
    password = request.form.get("mdp")

    if not username or not password:
        flash("Nom et mot de passe requis", "err")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Utilisateur inconnu. Crée d'abord un compte.", "err")
        return redirect(url_for("index"))

    if not check_password_hash(user.password_hash, password):
        flash("Mot de passe incorrect", "err")
        return redirect(url_for("index"))

    # OK → page articles
    log_user_login(username)
    
    # Auth Service : création du JWT et stockage dans la session
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=30)).timestamp())
    }
    token = jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")
    if not isinstance(token, str):
        token = token.decode("utf-8")

    # ✅ Sauvegarde du token en base
    user.auth_token = token
    user.token_expires_at = now + timedelta(minutes=30)
    db.session.commit()

    # ✅ on garde aussi le token en session
    session["jwt_token"] = token

    # panier vide au début
    session["panier"] = {}
    
    articles = [
        {"nom": "Ballon de football", "prix": 25.90},
        {"nom": "Chaussures de running", "prix": 79.99},
        {"nom": "Raquette de tennis", "prix": 89.50},
        {"nom": "Gants de boxe", "prix": 45.00},
        {"nom": "Tapis de yoga", "prix": 19.90},
        {"nom": "Casque de vélo", "prix": 39.90},
        {"nom": "Ballon de basket", "prix": 29.90},
        {"nom": "Haltères 5 kg", "prix": 34.90},
        {"nom": "Gourde inox 750 ml", "prix": 14.50},
        {"nom": "Short de sport", "prix": 22.90},
    ]
    return render_template("article.html", nom=username, articles=articles)

# Panier
@app.route("/api/article", methods=["GET", "POST"])
@jwt_required
def afficher_panier():
    if request.method == "GET":
        # si quelqu’un tape l’URL directement, on renvoie la liste d’articles
        nom = request.args.get("nom", "invité")
        articles = [
            {"nom": "Ballon de football", "prix": 25.90},
            {"nom": "Chaussures de running", "prix": 79.99},
            {"nom": "Raquette de tennis", "prix": 89.50},
            {"nom": "Gants de boxe", "prix": 45.00},
            {"nom": "Tapis de yoga", "prix": 19.90},
            {"nom": "Casque de vélo", "prix": 39.90},
            {"nom": "Ballon de basket", "prix": 29.90},
            {"nom": "Haltères 5 kg", "prix": 34.90},
            {"nom": "Gourde inox 750 ml", "prix": 14.50},
            {"nom": "Short de sport", "prix": 22.90},
        ]
        return render_template("article.html", nom=nom, articles=articles)

    nom = request.form.get("nom")

    articles_all = [
        {"nom": "Ballon de football", "prix": 25.90},
        {"nom": "Chaussures de running", "prix": 79.99},
        {"nom": "Raquette de tennis", "prix": 89.50},
        {"nom": "Gants de boxe", "prix": 45.00},
        {"nom": "Tapis de yoga", "prix": 19.90},
        {"nom": "Casque de vélo", "prix": 39.90},
        {"nom": "Ballon de basket", "prix": 29.90},
        {"nom": "Haltères 5 kg", "prix": 34.90},
        {"nom": "Gourde inox 750 ml", "prix": 14.50},
        {"nom": "Short de sport", "prix": 22.90},
    ]
    ref = {a["nom"]: a for a in articles_all}

    panier = []
    total = 0.0
    # Récupérer toutes les clés qty[...]
    for key, val in request.form.items():
        if key.startswith("qty[") and key.endswith("]"):
            nom_article = key[4:-1]              # ce qu'il y a entre les crochets
            try:
                qte = int(val or 0)
            except ValueError:
                qte = 0

            if qte > 0 and nom_article in ref:
                prix = ref[nom_article]["prix"]
                ligne = {
                    "nom": nom_article,
                    "prix": prix,
                    "quantite": qte,
                    "total": round(prix * qte, 2)
                }
                panier.append(ligne)
                total += ligne["total"]
                
    return render_template("confirmation.html", nom=nom, articles=panier, total=round(total, 2))

# Breaker
breaker_counter = 0
BREAKER_LIMIT = 3

@app.route("/api/commande", methods=["POST"])
@jwt_required
def passer_commande():
    global breaker_counter
    nom = request.form.get("nom")
    breaker_counter += 1
    bloque = breaker_counter >= BREAKER_LIMIT
    if bloque:
        breaker_counter = 0
    return render_template("banque.html", nom=nom, bloque=bloque)

@app.route("/retour-articles")
@jwt_required
def retour_articles():
    nom = request.args.get("nom")
    if not nom:
        return redirect(url_for("index"))
    return render_template("article.html", nom=nom, articles=[
        {"nom": "Ballon de football", "prix": 25.90},
        {"nom": "Chaussures de running", "prix": 79.99},
        {"nom": "Raquette de tennis", "prix": 89.50},
        {"nom": "Gants de boxe", "prix": 45.00},
        {"nom": "Tapis de yoga", "prix": 19.90},
        {"nom": "Casque de vélo", "prix": 39.90},
        {"nom": "Ballon de basket", "prix": 29.90},
        {"nom": "Haltères 5 kg", "prix": 34.90},
        {"nom": "Gourde inox 750 ml", "prix": 14.50},
        {"nom": "Short de sport", "prix": 22.90},
    ])
