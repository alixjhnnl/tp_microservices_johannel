# --------------------------------------------------------
# IMPORTS
# --------------------------------------------------------

"""manipuler chemins de fichiers et lire/écrire un JSON pour log de co"""
import os
import json

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
from datetime import datetime, timezone

""" écrire des décorateurs propres  """
from functools import wraps

# --------------------------------------------------------
# LOG USER CONNEXIONS DANS UN FICHIER JSON
# --------------------------------------------------------

def log_user_login(user_id: str):
    data_dir = os.path.join(app.root_path, "data") # construire le chemin à partir de la racine de l'app
    os.makedirs(data_dir, exist_ok=True) # crée le dossier data si besoin
    
    log_path = os.path.join(data_dir, "logins.json")

    try: #on essaye de lire le JSON
        with open(log_path, "r", encoding="utf-8") as f: # s'il existe on charge la liste 
            entries = json.load(f)
            if not isinstance(entries, list): # s'il n'existe pas ou que ce n'est pas une liste
                entries = []
    except FileNotFoundError:
        entries = []

    entries.append({ # on ajoute une entrée avec la date en ISO
        "user": user_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    with open(log_path, "w", encoding="utf-8") as f: # on réécrit le JSON complet sur le disque
        json.dump(entries, f, ensure_ascii=False, indent=2)

""" la sécurité repose sur l'user_id de la session, 
    preuve que l'utilisateur est connecté """
    
""" A chaque connexion réussie, je garde une trace dans data/logins.json
    donne un historique : quel user s'est co, à quel moment"""

# --------------------------------------------------------
# DÉCORATEUR "login_required" 
# --------------------------------------------------------

""" Toutes les routes annotées avec @login_required ne sont accessibles que si la session contient un user_id """
""" Sinon on bloque l'accès et on renvoie l'user sur la page de co avec un message """

""" JWT faisait le job dans la 1ere version avec un tocken JWT plutôt qu'avec la session Flask """

def login_required(f): # joue le rôle de barrière de sécurité 
    """
    Décorateur : protège une route.
    Dès qu’un utilisateur tente d’accéder à une route protégée le décorateur vérifie dans la session s’il existe une clé user_id.
    Si cette clé n’existe pas, j’en conclus que l’utilisateur n’est pas connecté.
    Dans ce cas, je renvoie l’utilisateur vers la page de connexion via un redirect et un message flash.
    Si la clé existe, alors la fonction originale peut s’exécuter.
    """
    @wraps(f) # garde le nom d'origine 
    def wrapper(*args, **kwargs):
        if "user_id" not in session: # on vérifie que user_id est dans la session
            flash("Tu dois être connecté pour accéder à cette page.", "err") # si ce n'est pas le cas, l'utilsateur n'est pas connecté donc on envoie un message flash + bloque l'accès à l'utilisateur en le renvoyant vers la page de login
            return redirect(url_for("index"))
        return f(*args, **kwargs) #sinon autorise l'accès et on exécute la route f

    return wrapper

    """
    Utile : 
        - aucune route sensible n'est accessible sans authenification
        - empêche un accès direct via l'URL
        - evite une exposition des données
        - garantit que le panier est lié à un utilisateur authentifié.
    """

""" Dans la première version, on avait implémenté un vrai système d'authentification JWT.
    Lorsqu'un utilisateur se connectait : 
        - Génération d'un JWT signé avec une clé secrète
        - ce JWT contenait les infos : username, date de création, date d'expiration
        - stockage du tocken à la fois dans la BDD et dans la session
    Pour chaque route protégé, on utilisait un décorateur jwt_required qui vérifiait : 
        - que le tocken existe 
        - qu'il n'a pas expiré
        - qu'il correspond exactement au tocken stocké dans la BDD pour le user
    Si un seul point échouait, l'accès était refusé.
    
    JWT : Auth Stateless (infos dans tocken, verif signature a chaque requete, aucune session serveur n'est necessaire
    Flask : Auth Stateful (infos dans serveur, garde l'état de co)"""
    
    
""" Si on voulait ajouter la possibilité via des comptes ext comme Google ou Apple, 
    on utiliserait OAuth2 et openID Connect
    Concrètement, j'aurais ajouter une route qui redirige l'user vers un page de login google ou apple, 
    puis une route où Google renvoie les infos d'ID
    A partir de ces infos, on aurait pu créer oub retrouver l'user dans notre BDD avant de stocker son ID dans Flask, 
    comme pour un co classique."""

# --------------------------------------------------------
#  ROUTE PAGE D'ACCUEIL / LOGIN
# --------------------------------------------------------

""" Quand on arrive sur la racine du site, on rend le template index.html (page de co : formulaire login + création de compte)"""

@app.route("/")
def index(): 
    return render_template("index.html")

# --------------------------------------------------------
#  ROUTE D'INSCRIPTION /register
# --------------------------------------------------------
"""Permet de créer un compte : 
    - GET : affiche le formulaire d'inscription
    - POST : 
        + on récupère les champs nom/mdp
        + on vérifie qu'ils ne sont pas vides
        + on vérifie que le username n'existe pas déjà dans la BDD
        + on hache le mdp avec generate_password_hash
        + on crée un nouvel objet User et on commit 
        + On affiche un flash "compte créé" et on renvoie vers / pour se connecter 
"""
        
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
        
        """/register crée des user en stockant uniquement un hash du mdp, jamais le mdp en clair"""
        
        user = User(username=username, password_hash=hash_pw)
        db.session.add(user)
        db.session.commit()
        
        flash("Compte créé — tu peux te connecter.", "ok")
        return redirect(url_for('index'))


    return render_template('register.html')  # Si GET : on affiche la page register.html

# --------------------------------------------------------
#  ROUTE DE CONNEXION /api/utilisateurs
# --------------------------------------------------------

""" route de login, récupère user et mdp depuis le formulaire."""

@app.route("/api/utilisateurs", methods=["POST"])
def ajouter_utilisateur():
    """
    PUBLIQUE
    Traite le formulaire de connexion :
    - Vérifie les champs non vides,
    - Vérifie que l'utilisateur existe (user.query.filter_by(user...))
    - Vérifie mdp correct via check_password_hash
    
    En cas d'erreur : flash + redirect vers la page de login
    
    En cas de succès :
    - Log via log_user_login(user)
    - Stocke les infos dans la session Flask
    - Redirige vers la page des articles
    """
    
    #cette page joue le rôle d'Auth Service : elle vérifie les ID, initialise la session pour cet utilisateur, 
    #puis redirige vers la page catalogue avec un panier vide
    
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
@login_required #route protégée
def afficher_panier():
    """
    PRIVEE
    - GET : si quelqu'un tape l'URL directement, on réaffiche la liste d'articles
    - POST : on lit les quantités du formulaire et on construit le panier
    """
    nom = session.get("username", "invité") # Nom de l'utilisateur pour affichage : on le récupère depuis la session
    
    articles_all = [ #catalogue complet
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
    
    ref = {a["nom"]: a for a in articles_all} # dictionnaire de lookup, donne l'objet article (prix)
    
    panier_session = session.get("panier", {}) # panier sauvegardé dans la session (permet de garder les choix déjà enregistrés)
    
    # --------- liste articles ---------
    
    """ si on clique sur "continuer les achats", on renvoie la page des articles"""
   
    if request.method == "GET": #affiche liste articles
        return render_template("article.html", nom=nom, articles=articles_all)

    for key, val in request.form.items(): # mise à jour du panier
        if key.startswith("qty[") and key.endswith("]"):
            nom_article = key[4:-1]  # récupère ce qu'il y a entre les crochets
            
            try:
                qte = int(val or 0)
            except ValueError:
                qte = 0

            # Mise à jour du panier
            if qte > 0:
                panier_session[nom_article] = qte
                
    """ on lit tous les champs du formulaire
        les inputs dans le HTML sont de la forme name="qty[Nom de l'article]
        on extrait le nom des articles à partir de la clé
        on convertit la valeur en entier (qte)
        si qte > 0, on maj le dict panier_session
        on sauvegarde tout le panier dans session["panier"]"""
            
    session["panier"] = panier_session
    """ chaque fois qu'on ajoute ou retire un article, on met simplement à jour ce dictionnaire
        Avantages : 
            + persiste tq session vit 
            + lié à user connecté
            + aucun BDD nécessaire"""
    
    # construction de l'écran de confirmation, maj panier
    panier = [] 
    total = 0.0
    
    # On reconstruit la liste détaillée pour la confirmation : nom,  prix unitaire, quantité, total 
    for nom_article, qte in panier_session.items():
        if nom_article in ref:
            prix = ref[nom_article]["prix"]
            ligne_total = round(prix * qte, 2) # calcul total panier
            panier.append({
                "nom": nom_article,
                "prix": prix,
                "quantite": qte,
                "total": ligne_total,
            })
            total += ligne_total

    return render_template("confirmation.html", nom=nom, articles=panier, total=round(total, 2))

    """ lit aquantités envoyées par le formulaire, maj le panier stocké dans la session et affiche un récap détaillé"""
    
# --------------------------------------------------------
#  BREAKER /api/commande
# --------------------------------------------------------

""" simulation : après 3 appels, on considère que le service bancaire est en panne
    il sert à éviter que toutes l'app plante"""

breaker_counter = 0 # nb d'appels consécutifs au service paiement
BREAKER_LIMIT = 3 # seuil à partir duquel on déclare le service bloqué

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

""" A chaque /api/commande : 
    - on incrémente breaker_counter
    - si on a atteint le sueil : bloque=True et on réinitialise le compteur
    
    Le template banque.html affiche soit "paiement ok" soit "circuit breaker déclenché"""

# --------------------------------------------------------
#  RETOUR AUX ARTICLES /retour-articles
# --------------------------------------------------------

@app.route("/retour-articles")
@login_required
def retour_articles():
    """
    Permet de revenir à la page des articles tout en sauvegardant le panier.
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

""" Quand on clique sur continuer achats,  on revient au catalogue, mais le panier est sauvegardé donc le user ne perd pas sa précédente sélection"""