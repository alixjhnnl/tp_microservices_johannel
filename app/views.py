import os
import json

from flask import render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

from app.models import User
from app import app, db

from datetime import datetime, timezone
from functools import wraps

# --------------------------------------------------------
# LOG USER CONNEXIONS DANS UN FICHIER JSON
# --------------------------------------------------------

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

# --------------------------------------------------------
# DÉCORATEUR "login_required" 
# --------------------------------------------------------

def login_required(f):
    """
    Décorateur : protège une route. Si l'utilisateur n'est pas connecté 
    (pas de user_id dans la session), on le renvoie à la page de login.
    """
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Tu dois être connecté pour accéder à cette page.", "err")
            return redirect(url_for("index"))
        return f(*args, **kwargs)

    return wrapper

# --------------------------------------------------------
#  ROUTE PAGE D'ACCUEIL / LOGIN
# --------------------------------------------------------

@app.route("/")
def index(): 
    return render_template("index.html")

# --------------------------------------------------------
#  ROUTE D'INSCRIPTION /register
# --------------------------------------------------------
"""Permet de créer un compte : 
    - GET : affiche le formulaire d'inscription
    - POST : traite le formulaire, crée un utilisateur en base"""
        
@app.route('/register', methods=['GET', 'POST'])
def register(): 
  
    if request.method == 'POST':
        username = request.form.get('nom')
        password = request.form.get('mdp')
        
        if not username or not password: # Vérifie remplissage des champs
            flash("Erreur remplissage", "err")
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first(): # Vérifie si username déjà pris
            flash("Nom d'utilisateur déjà pris", "err")
            return redirect(url_for('register'))

        hash_pw = generate_password_hash(password) # Hachage du mot de passe pour ne jamais le stocker en clair
        
        user = User(username=username, password_hash=hash_pw)
        db.session.add(user)
        db.session.commit()
        
        flash("Compte créé — tu peux te connecter.", "ok")
        return redirect(url_for('index'))


    return render_template('register.html')  # Si GET : on affiche la page register.html

# --------------------------------------------------------
#  ROUTE DE CONNEXION /api/utilisateurs
# --------------------------------------------------------

@app.route("/api/utilisateurs", methods=["POST"])
def ajouter_utilisateur():
    """
    PUBLIQUE
    Traite le formulaire de connexion.
    - Vérifie que l'utilisateur existe
    - Vérifie le mot de passe (hash)
    - Stocke les infos dans la session Flask
    - Redirige vers la page des articles
    """
    username = request.form.get("nom")
    password = request.form.get("mdp")

    if not username or not password:
        flash("Nom et mot de passe requis", "err")
        return redirect(url_for("index"))

    user = User.query.filter_by(username=username).first() # On cherche l'utilisateur dans la base
    if user is None:
        flash("User not found. Crée un compte.", "err")
        return redirect(url_for("index"))

    if not check_password_hash(user.password_hash, password): # Vérification du mot de passe (comparaison hash)
        flash("Mot de passe incorrect", "err")
        return redirect(url_for("index"))

    # Si tout est OK :
    # - on loggue la connexion dans logins.json
    # - on met les infos dans la session
    log_user_login(username) 
    
    session["user_id"] = user.id        
    session["username"] = user.username # affichage
    session["panier"] = {}              # panier vide au début de la session
    
    articles = [   # Liste fixe d'articles (catalogue)
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
    # On envoie l'utilisateur sur la page des articles
    return render_template("article.html", nom=username, articles=articles)

# --------------------------------------------------------
#  ROUTE PANIER /api/article
# --------------------------------------------------------
@app.route("/api/article", methods=["GET", "POST"])
@login_required
def afficher_panier():
    """
    PRIVEE
    - GET : si quelqu'un tape l'URL directement, on réaffiche la liste d'articles
    - POST : on lit les quantités du formulaire et on construit le panier
    """
    nom = session.get("username", "invité") # Nom de l'utilisateur pour affichage : on le récupère depuis la session
    
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
    
    panier_session = session.get("panier", {})
    
    # --------- liste articles ---------
    if request.method == "GET":
        return render_template("article.html", nom=nom, articles=articles_all)

    for key, val in request.form.items(): # Les input du formulaire ont une forme : name="qty[Nom de l'article]"
        if key.startswith("qty[") and key.endswith("]"):
            nom_article = key[4:-1]  # récupère ce qu'il y a entre les crochets
            
            try:
                qte = int(val or 0)
            except ValueError:
                qte = 0

            # Mise à jour du panier
            if qte > 0:
                panier_session[nom_article] = qte
            
            
    session["panier"] = panier_session
    
    # on lit le formulaire et on met à jour le panier
    panier = [] 
    total = 0.0
    
    # On reconstruit la liste détaillée pour la confirmation
    for nom_article, qte in panier_session.items():
        if nom_article in ref:
            prix = ref[nom_article]["prix"]
            ligne_total = round(prix * qte, 2)
            panier.append({
                "nom": nom_article,
                "prix": prix,
                "quantite": qte,
                "total": ligne_total,
            })
            total += ligne_total

    return render_template("confirmation.html", nom=nom, articles=panier, total=round(total, 2))
    
# --------------------------------------------------------
#  BREAKER /api/commande
# --------------------------------------------------------

breaker_counter = 0
BREAKER_LIMIT = 3

@app.route("/api/commande", methods=["POST"])
@login_required
def passer_commande(): 
    """
    Simule un service de paiement avec breaker :
    - après un certain nombre d'appels, on considère que le service est "bloqué"
    """
    global breaker_counter
    nom = session.get("username", "invité")
    
    breaker_counter += 1
    bloque = breaker_counter >= BREAKER_LIMIT
    
    if bloque:
        breaker_counter = 0 # On "reset" le breaker après déclenchement
        
    return render_template("banque.html", nom=nom, bloque=bloque)

# --------------------------------------------------------
#  RETOUR AUX ARTICLES /retour-articles
# --------------------------------------------------------

@app.route("/retour-articles")
@login_required
def retour_articles():
    """
    Permet de revenir à la page des articles depuis la confirmation.
    """
    nom = session.get("username", "invité")
    
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
    
    quantites = session.get("panier", {})

    return render_template("article.html", nom=nom, articles=articles, quantites=quantites)
