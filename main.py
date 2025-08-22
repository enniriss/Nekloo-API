from function import *
from passlib.hash import pbkdf2_sha256
import os
from firebase_admin import auth
from flask_cors import CORS  # Nécessite pip install flask-cors

app = Flask(__name__)
# Activer CORS pour toute l'application
CORS(app)

JWT_SECRET = os.urandom(24)
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 1440

########### User ###########
@app.route('/user/create', methods=['POST'])
def create_user():
    try:
        document_data = request.json
        vagabond_docs = db.collection('vagabond').where('email', '==', document_data['email']).get()
        admin_docs = db.collection('admin').where('email', '==', document_data['email']).get()
        print(vagabond_docs)
        if vagabond_docs or admin_docs:
            return jsonify({"error": "Email déjà utilisé"}), 400
        document_data["password"] = pbkdf2_sha256.hash(document_data["password"])
        
        document_data["role"] = "vagabond"
        document_data["created_time"] = datetime.now()
        create_document("vagabond", document_data)

        return jsonify({"success": True}), 200
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    

@app.route('/user/read/<document_id>', methods=['GET'])
@admin_or_vagabond_required
def get_my_user(document_id):
    try:
        print("document_id", document_id)
        document_data = read_document("vagabond", document_id)
        print("document_data", document_data)

        vagabond_check = read_document("vagabond", document_id)
        admin_check = read_document("admin", document_id)

        if admin_check:
            admin_check["role"] = "admin"
            return jsonify(admin_check), 200
        elif vagabond_check:
            vagabond_check["role"] = "vagabond"
            return jsonify(vagabond_check), 200
        return jsonify({"success": True, "error": "not allowed"}), 403
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/login', methods=['POST'])
def login():
    try:
        # Récupération des données de la requête
        data = request.json
        if not data:
            return jsonify({"error": "Données manquantes"}), 400
            
        email = data.get('email')
        password = data.get('password')
        
        if not email or not password:
            return jsonify({"error": "Email ou mot de passe déjà utilisé"}), 409
        
        # Vérification de l'authentification admin
        admin_docs = db.collection('admin').where('email', '==', email).get()
        
        if admin_docs:
            admin = admin_docs[0].to_dict()
            if pbkdf2_sha256.verify(password, admin["password"]):
                # Création d'un token JWT pour l'admin
                token = create_token(admin, "admin")
                
                return jsonify({
                    "status": "success",
                    "message": "Connexion réussie en tant qu'administrateur",
                    "token": token,
                    "role": "admin",
                    "user_data": {
                        "email": admin["email"],
                        "id": admin_docs[0].id,
                        "pseudo": admin["pseudo"],      
                    }
                }), 200
        
        # Si ce n'est pas un admin, vérifions si c'est un vagabond
        vagabond_docs = db.collection('vagabond').where('email', '==', email).get()
        
        if vagabond_docs:
            vagabond = vagabond_docs[0].to_dict()
            if pbkdf2_sha256.verify(password, vagabond["password"]):
                # Création d'un token JWT pour le vagabond
                token = create_token(vagabond, "vagabond")
                print("vagabond", vagabond)
                return jsonify({
                    "status": "success",
                    "message": "Connexion réussie en tant que vagabond",
                    "token": token,
                    "role": "vagabond",
                    "user_data": {
                        "email": vagabond["email"],
                        "id": vagabond_docs[0].id,
                        "pseudo": vagabond["pseudo"], 
                    }
                }), 200
        
        # Si on arrive ici, c'est que les identifiants sont incorrects
        return jsonify({"error": "Email ou mot de passe incorrect"}), 401
        
    except Exception as e:
        print(f"Erreur lors de la connexion: {str(e)}")
        return jsonify({"error": "Une erreur est survenue lors de la connexion"}), 500


@app.route('/logout', methods=['POST'])
def logout():
    try:
        # Récupérer le token depuis les headers
        auth_header = request.headers.get('Authorization')
        
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({"error": "Token d'authentification manquant"}), 401
            
        token = auth_header.split(' ')[1]
        
        # Option 1: Si vous utilisez une liste noire de tokens (recommandé)
        # Ajouter le token à une liste noire dans Firebase
        blacklist_ref = db.collection('token_blacklist')
        blacklist_ref.add({
            'token': token,
            'invalidated_at': datetime.utcnow(),
            'expires_at': get_token_expiry(token)
        })
        
        return jsonify({
            "status": "success",
            "message": "Déconnexion réussie"
        }), 200
        
    except Exception as e:
        print(f"Erreur lors de la déconnexion: {str(e)}")
        return jsonify({"error": "Une erreur est survenue lors de la déconnexion"}), 500


############ Places ###########


@app.route('/places', methods=['GET'])
@admin_or_vagabond_required
def get_all_places(collection_name):
    try:
        places = read_all_documents("places")
        
        return jsonify({"success": True, "data": places}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/places/<document_id>', methods=['GET'])
@admin_or_vagabond_required
def get_place(document_id):
    try:
        place = read_document("places", document_id)      
        return jsonify({"success": True, "data": place}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    

@app.route('/places/create', methods=['POST'])
@admin_required
def create_place():
    try:
        document_data = request.json                
        create_document("places", document_data)
        return jsonify({"success": True}), 200
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



############ Suppositions ###########
@app.route('/user/<user_id>/supposition/create', methods=['POST'])
@vagabond_required
def create_supposition(user_id):
    try:
        doc_ref = db.collection("suppositions").document()
        print("1. doc_ref", doc_ref)
        document_data = request.json
        print("2. document_data", document_data)
        print("3. create_document", user_id)
        print(read_all_document_ready(doc_ref))
        create_document_new(["suppositions", "supposition"], document_data, [user_id, None])
        return jsonify({"success": True, "id": user_id}), 201
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/user/<user_id>/supposition/read', methods=['GET'])
@vagabond_required
def get_user_suppositions(user_id):
    try:
        suppositions = db.collection("suppositions").document(user_id).collection("supposition")
        final_doc = read_all_document_ready(suppositions)

        return jsonify({"success": True, "data": final_doc}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
@app.route('/supposition/readall', methods=['GET'])
@admin_required
def get_all_suppositions():
    try:
        datas = []
        suppositions_user = db.collection("suppositions")
        for su in suppositions_user.list_documents():
            final_doc = read_all_document_ready(suppositions_user.document(su.id).collection("supposition"))
            dico = {"user_info" : {"id" : su.id, "pseudo" : read_document("vagabond", su.id)["pseudo"]}, "suppositions" : final_doc}
            print("dico", dico)
            datas.append(dico)
        print("datas", datas)
        return jsonify({"success": True, "data": datas}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    

########## Likes ###########
@app.route('/like/<vagabond_id>/<place_id>', methods=['POST'])
@vagabond_required
def like():
    try:
        document_data = request.json
        user_likes = read_document("vagabond", vagabond_id)["likes"]
        if place_id not in user_likes:
            user_likes.append(document_data["like"])
        else:
            user_likes.remove(document_data["like"])
        update_document("vagabond", vagabond_id,user_likes)
        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route('/user/like/<vagabond_id>', methods=['GET'])
@vagabond_required
def get_like():
    try:
        places_liked = read_document("vagabond", vagabond_id)["likes"]
        return jsonify(places_liked), 200        
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


#### Activity ######

@app.route('/activity/create', methods=['POST'])
@admin_required
def create_activity():
    try:
        document_data = request.json
        activity_docs = db.collection('activity').where('name', '==', document_data['name']).get()
        if activity_docs:
            return jsonify({"error": "Nom déjà utilisé"}), 400
        create_document("activity", document_data)
        return jsonify({"success": True}), 200
    
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route('/activity/readall', methods=['GET'])
@admin_or_vagabond_required
def get_all_activity():
    try:
        places = read_all_documents("activity")
        print("places", places)
        return jsonify({"success": True, "data": places}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500



@app.route('/')
def waw():
    return "waw"

@app.route('/pipi')
def pipi():
    return "pipi"


if __name__ == "__main__":
  app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))