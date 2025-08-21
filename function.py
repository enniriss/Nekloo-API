import firebase_admin
from firebase_admin import credentials, firestore
cred = credentials.Certificate("./params.json")
firebase_admin.initialize_app(cred)
db = firestore.client()
import datetime
import os
import jwt
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, g
from functools import wraps

### Search collection
def search_collection(collection_list):
    messages_ref = db.collection(collection_list[0]).document(collection_list[1])
    print(messages_ref)
    for collection in collection_list[1:]:
        messages_ref = messages_ref.collection(collection)
    print(messages_ref)
    return messages_ref


### CRUD
# CREATE
def create_document(collection_name, document_data, document_id=None):
    collection_ref = db.collection(collection_name)
    
    if document_id:
        doc_ref = collection_ref.document(document_id)
        doc_ref.set(document_data)
        return document_id

    else:
        doc_ref = collection_ref.add(document_data)
        return doc_ref[1].id
    
def create_document_new(collection_name, document_data, document_id=None):
    collection_ref = db.collection(collection_name[0]).document(document_id[0])

    for col, doc in zip(collection_name[1:-1], document_id[1:-1]):
        print(zip(collection_name[1:], document_id[1:]))
        print("col", col)
        collection_ref = collection_ref.collection(col).document(doc)

    print("collection_ref")
    target_collection = collection_ref.collection(collection_name[-1])
    target_collection.add(document_data)
    return "success"
# UPDATE
def update_document(collection_name, document_id, document_data):
    doc_ref = db.collection(collection_name).document(document_id)
    doc_ref.update(document_data)
    return True

# DELETE
def delete_document(collection_name, document_id):
    db.collection(collection_name).document(document_id).delete()
    return True

# READ
def read_document(collection_name, document_id):
    doc_ref = db.collection(collection_name).document(document_id)
    doc = doc_ref.get()
    print("doc", doc.to_dict())
    if doc.exists:
        return doc.to_dict()

    else:
        return None

# READ ALL
def read_all_documents(collection_name):
    docs = db.collection(collection_name).stream()
    result = []

    for doc in docs:
        doc_data = doc.to_dict()
        doc_data['id'] = doc.id
        result.append(doc_data)

    return result

def read_all_document_ready(ref):
    # Document
    try:
        doc = ref.get()
        if doc.exists:
            return doc.to_dict()
        else:
            return None
    except Exception as e:
        pass
    try:
        col = ref.stream()
        result = []
        for doc in col:
            print("doc", doc)
            print("doc.id", doc.id)
            doc_data = doc.to_dict()
            doc_data['id'] = doc.id
            result.append(doc_data)
        return result
    except Exception as e:
        pass

    return None
        

def create_token(user_data, user_type):
    # Durée de validité du token: 24 heures
    expiration = datetime.utcnow() + timedelta(hours=24)
    
    payload = {
        "user_id": user_data.get("id", ""),
        "email": user_data.get("email", ""),
        "user_type": user_type,
        "exp": expiration
    }
    
    # Créer le token avec une clé secrète (à définir dans vos variables d'environnement)
    secret_key = os.environ.get("JWT_SECRET_KEY", "votre_cle_secrete_par_defaut")
    token = jwt.encode(payload, secret_key, algorithm="HS256")
    
    return token

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Récupérer le token depuis les headers
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
            
        if not token:
            return jsonify({'error': 'Token d\'authentification manquant'}), 401
            
        try:
            # Vérifier si le token est dans la liste noire
            blacklist_ref = db.collection('token_blacklist')
            if blacklist_ref.where('token', '==', token).get():
                return jsonify({'error': 'Token invalide ou expiré'}), 401
                
            # Vérifier et décoder le token
            secret_key = os.environ.get("JWT_SECRET_KEY", "votre_cle_secrete_par_defaut")
            payload = jwt.decode(token, secret_key, algorithms=["HS256"])
            print("Payload:", payload)
            # Vérifier si le token est expiré
            if datetime.fromtimestamp(payload['exp']) < datetime.utcnow():
                return jsonify({'error': 'Token expiré'}), 401
                
            # Stocker les informations du token pour l'utilisation dans la fonction
            g.user_id = payload.get('_id')
            g.email = payload.get('email')
            g.role = payload.get('role')
            
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expiré'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Token invalide'}), 401
        except Exception as e:
            return jsonify({'error': f'Erreur lors de la validation du token: {str(e)}'}), 401
            
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Utiliser d'abord le middleware token_required
        token_result = token_required(lambda: None)()
        if isinstance(token_result, tuple):  # En cas d'erreur
            return token_result
            
        # Vérifier si l'utilisateur est un admin
        if f.role != 'admin':
            return jsonify({'error': 'Accès non autorisé. Droits d\'administrateur requis'}), 403
            
        return f(*args, **kwargs)
    return decorated


def vagabond_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        print("Vagabond ca maman")
        # Utiliser d'abord le middleware token_required
        token_result = token_required(lambda: None)()
        if isinstance(token_result, tuple):  # En cas d'erreur
            return token_result
            
        # Vérifier si l'utilisateur est un vagabond
        if f.role != 'vagabond':
            return jsonify({'error': 'Accès non autorisé. Droits de vagabond requis'}), 403
            
        return f(*args, **kwargs)
    return decorated

def admin_or_vagabond_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Utiliser d'abord le middleware token_required
        token_result = token_required(lambda: None)()
        if isinstance(token_result, tuple):  # En cas d'erreur
            return token_result
            
        # Vérifier si l'utilisateur est un admin ou un vagabond
        if f.user_type not in ['admin', 'vagabond']:
            return jsonify({'error': 'Accès non autorisé. Droits d\'admin ou de vagabond requis'}), 403
            
        return f(*args, **kwargs)
    return decorated


def get_token_expiry(token):
    try:
        # Décodage sans vérification (juste pour obtenir l'expiration)
        payload = jwt.decode(token, options={"verify_signature": False})
        if 'exp' in payload:
            return datetime.fromtimestamp(payload['exp'])
    except:
        pass
    # Par défaut, on considère que le token expire dans 24h
    return datetime.utcnow() + timedelta(hours=24)