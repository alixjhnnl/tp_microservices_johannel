# --------------------------------------------------------
# IMPORTS
# --------------------------------------------------------

"""manipuler chemins de fichiers et lire/écrire un JSON pour log de co"""
import os
import json
import jwt

from flask import render_template, request, redirect, url_for, flash, session
""" render_template : afficher une page HTML
    request : récupérer les données du formulaire (login, quantités...)
    redirect, url_for : rediriger vers une autre route 
    flash : envoyer un petit msg temporaire à afficher dans la page
    session : stockage côté serveur des infos user (id, username, panier) """

from werkzeug.security import generate_password_hash, check_password_hash
""" generate_password_hash : hacher le mdp
    check_password_hash : comparer un mdp saisi au hash stocké en base"""

from app.models import User
from app import app, db

""" pour dater les connexions """
from datetime import datetime, timezone, timedelta

""" écrire des décorateurs propres  """
from functools import wraps

# --------------------------------------------------------
# CONFIG JWT (JSON WEB TOCKENS)
# --------------------------------------------------------

""" clé secrète utilisée pour signer les JWT 
    on la récupère dans la config de Flask (même SECRET_KEY que pour les sessions)"""

JWT_SECRET = app.config['SECRET_KEY']     

""" Algo de signature tocken"""  
JWT_ALGO = "HS256"

""" Durée de vie du tocken (en min)"""
JWT_EXP_MINUTES = 1 

# --------------------------------------------------------
# CREATION/VERIFICATION JWT (JSON WEB TOCKENS)
# --------------------------------------------------------

""" Principe : stateless
    
    A la création : génération d'un tocken JWT signé avec la clé secrète.
    ce tocken contient :
        + sub : username
        + iat : date d'émission
        + exp : date d'expiration
    on stocke ce tocken:
        + dans la session (gateway)
        + BDD (auth_tocken du user)
    
    pour chaque route protégée : 
        + la décorateur jwt_required récupère le tocken dans la session 
        + il appelle verify_jwt qui : 
            - décode et vérifie la signature
            - vérifie que le tocken n'est pas expiré 
            - vérifie que le tocen match celui en BDD
    
    Si tout bon : on laisse passer la requête
    Si une condition échoue, l'accès est refusé, user redirigé vers page login """
 
def create_jwt(username: str) -> str:  
    
    """ fabrique un JWT pour un user donné
        retourne une châine (tocken signé)"""
        
    now = datetime.now(timezone.utc) # éviter pb de fuseaux horaires
    payload = {
        "sub": username, # identifie l'utilisateur
        "iat": int(now.timestamp()), #date d'émission
        "exp": int((now + timedelta(minutes=JWT_EXP_MINUTES)).timestamp()) #date d'expiration
    }
    
    #jwt.encode renvoie un tocken signé 
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)
    return token if isinstance(token, str) else token.decode("utf-8")

def verify_jwt(token: str):
    """ Vérifie un JWT et cohérence avec la base. 
        Renvoie le payload décodé si tout va bien, sinon None."""
    
    try: # décodage + vérification de la signature et de l'expiration
        payload = jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        # le tocken est valide mais la date d'expiration est dépassée
        return None
    except jwt.InvalidTokenError:
        # signature incorrecte ou tocken mal formé
        return None

    """ vérifie qu'on a bien un sub dans le payload"""
    username = payload.get("sub")
    if not username:
        return None

    """ récupérer le user en base """
    user = User.query.filter_by(username=username).first()
    if user is None:
        # le tocken fait référence à un user qui n'existe plus
        return None

    """ vérifie que le token fourni est bien le même que celui stocké en BDD
        sinon, un vieux tocken ou un tocken volé sera refusé """
    if user.auth_token != token:
        return None

    """ vérifie la date d'expiration stockée en base """
    if not user.token_expires_at:
        return None

    # Normalisation : on rend la date "aware" si elle est naive
    expires = user.token_expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)

    # Comparaison avec l'heure actuelle (aware elle aussi)
    if expires < datetime.now(timezone.utc):
        return None

    # si tout OK : on renvoie le payload décodé
    return payload

# --------------------------------------------------------
# TRANSPORT TOCKENS : DECORATEUR jwt _required
# --------------------------------------------------------

def jwt_required(f):
    """ décorateur : protègeune route 
        vérifie qu'un JWT valide est présent avant d'accéder à la route."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        # récupérer le tocken dans la session (stocké à la co)
        token = session.get("jwt_token")
        if not token:
            # aucun tocken : user non authentifié 
            flash("Tu dois être connecté pour accéder à cette ressource.", "err")
            return redirect(url_for("index"))

        # vérifier le tocken (signature, expiration, cohérence BDD)
        payload = verify_jwt(token)
        if payload is None:
            # tocken invalide ou expiré
            flash("Session expirée ou invalide. Reconnecte-toi.", "err")
            # on nettoie le token invalide
            session.pop("jwt_token", None)
            return redirect(url_for("index"))

        # si tout ok, on laisse la fonction originale s'éxécuter
        # on peut récupérer le username depuis payload["sub"] si besoin
        return f(*args, **kwargs)
    return wrapper

# --------------------------------------------------------
# LOG DES CO USER (FICHIER JSON)
# --------------------------------------------------------

""" Enregistre chaque co réussie dans un fichier data/logins.json """

def log_user_login(user_id: str):
    data_dir = os.path.join(app.root_path, "data")
    os.makedirs(data_dir, exist_ok=True) # crée ke dossier si nécessaire
    
    log_path = os.path.join(data_dir, "logins.json")

    try: # on essaie de lire le fichier existant pour récupérer les logs précédents
        with open(log_path, "r", encoding="utf-8") as f:
            entries = json.load(f)
            if not isinstance(entries, list):
                entries = []
    except FileNotFoundError:
        # fichier non existant
        entries = []

    entries.append({
        "user": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    # on réécrit le fichier complet
    with open(log_path, "w", encoding="utf-8") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
        
# --------------------------------------------------------
#  ROUTE PAGE D'ACCUEIL / LOGIN
# --------------------------------------------------------

@app.route("/")
def index():
    """ page de login. Affiche la page d'accuail avec le formulaire de connexion"""
    return render_template("index.html")

# --------------------------------------------------------
#  ROUTE D'INSCRIPTION /register
# --------------------------------------------------------

# Inscription (optionnelle)
@app.route('/register', methods=['GET', 'POST'])
def register():
    """ GET : affiche formulaire création compte
        POST : traite le formulaire et crée l'user en BDD avec mdp haché"""
   
    if request.method == 'POST':
        username = request.form.get('nom')
        password = request.form.get('mdp')

        # vérifie que les deux champs sont remplis 
        if not username or not password:
            flash("Remplis nom et mot de passe", "err")
            return redirect(url_for('register'))
        
        # vérifie si username deja pris
        if User.query.filter_by(username=username).first():
            flash("Nom d'utilisateur déjà pris", "err")
            return redirect(url_for('register'))

        # Hache mdp et crée user
        hash_pw = generate_password_hash(password)
        user = User(username=username, password_hash=hash_pw)
        db.session.add(user)
        db.session.commit()
        
        flash("Compte créé — tu peux te connecter.", "ok")
        return redirect(url_for('index'))
    
    # Si GET : on affoche simplement la page d'inscription
    return render_template('register.html') 

# --------------------------------------------------------
#  ROUTE DE CONNEXION /api/utilisateurs
# --------------------------------------------------------

@app.route("/api/utilisateurs", methods=["POST"])
def ajouter_utilisateur():
    
    """ Route publique de login :
    - vérifie id
    - loggue la connexion
    - génère JWT et le stocke (session + BDD)
    - initialise panier vide en session
    - renvoie page de sélection des articles """
    
    username = request.form.get("nom")
    password = request.form.get("mdp")
    
    # vérifie champs 
    if not username or not password:
        flash("Nom et mot de passe requis", "err")
        return redirect(url_for("index"))

    # vérifie existance username
    user = User.query.filter_by(username=username).first()
    if user is None:
        flash("Utilisateur inconnu. Crée d'abord un compte.", "err")
        return redirect(url_for("index"))

    # vérifie mdp (haché)
    if not check_password_hash(user.password_hash, password):
        flash("Mot de passe incorrect", "err")
        return redirect(url_for("index"))

    # Tout ok : on logge ds JSON
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

    # Sauvegarde du token en base dans BDD
    user.auth_token = token
    user.token_expires_at = now + timedelta(minutes=30)
    db.session.commit()

    # Sauvegarde du tocken dans session
    session["jwt_token"] = token

    # Initialisation panier vide au début
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
    
    # on envoie user sur page de selection articles
    return render_template("article.html", nom=username, articles=articles)

# --------------------------------------------------------
#  ROUTE PANIER /api/article
# --------------------------------------------------------

@app.route("/api/article", methods=["GET", "POST"])
@jwt_required # protection par tocken : impossible d'y accéder sans etre logger
def afficher_panier():
    
    """ GET  : renvoie la liste d’articles (si quelqu’un tape l’URL directement)
        POST : lit les quantités du formulaire et construit le panier
    """
    
    if request.method == "GET":
        # on renvoie la liste d’articles
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
    
    # Si POST : on construit le panier à partir des quantités
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
            nom_article = key[4:-1] # ce qu'il y a entre les crochets
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
      
    # On envoie la page de confirmation avec le détail du panier          
    return render_template("confirmation.html", nom=nom, articles=panier, total=round(total, 2))

# --------------------------------------------------------
#  BREAKER /api/commande
# --------------------------------------------------------

# Compteur global pour simuler un "circuit breaker"
breaker_counter = 0 # nombre d’appels consécutifs
BREAKER_LIMIT = 3 # seuil à partir duquel on considère que le service est en panne

@app.route("/api/commande", methods=["POST"])
@jwt_required
def passer_commande():
    """
    Simule un service de paiement protégé par un breaker.
    Après un certain nombre d’appels, on considère que le service est "bloqué".
    """
    global breaker_counter
    nom = request.form.get("nom")
    
    breaker_counter += 1
    bloque = breaker_counter >= BREAKER_LIMIT
    
    if bloque:
        # On "ouvre" le breaker et on reset le compteur après blocage
        breaker_counter = 0
    return render_template("banque.html", nom=nom, bloque=bloque)

# --------------------------------------------------------
#  RETOUR AUX ARTICLES /retour-articles
# --------------------------------------------------------

@app.route("/retour-articles")
@jwt_required
def retour_articles():
    """
    Permet de revenir à la page des articles depuis la confirmation.
    Toujours protégé par JWT.
    """
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
