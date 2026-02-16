import requests
from datetime import datetime

from flask import request, jsonify, Blueprint
from flask_cors import CORS
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, decode_token
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import ( db, User, )


api = Blueprint('api', __name__)

# Allow CORS requests to this API
CORS(api)

@api.route("/auth/register", methods=["POST"])
def register():
    body = request.get_json() or {}
    email = (body.get("email") or "").strip().lower()
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    if not email or not username or not password:
        return jsonify({"error": "email, username y password son requeridos"}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({"error": "email ya existe"}), 409

    if User.query.filter_by(username=username).first():
        return jsonify({"error": "username ya existe"}), 409

    user = User(
        email=email,
        username=username,
        password_hash=generate_password_hash(password),
        is_active=True
    )
    db.session.add(user)
    db.session.commit()

    token = create_access_token(identity=str(user.id))
    return jsonify({"user": user.serialize(), "token": token}), 201


@api.route("/auth/login", methods=["POST"])
def login():
    body = request.get_json() or {}
    email = (body.get("email") or "").strip().lower()
    password = body.get("password") or ""

    if not email or not password:
        return jsonify({"error": "email y password son requeridos"}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "credenciales inválidas"}), 401

    token = create_access_token(identity=str(user.id))
    return jsonify({"user": user.serialize(), "token": token}), 200


@api.route('/hello', methods=['POST', 'GET'])
def handle_hello():

    response_body = {
        "message": "Hello! I'm a message that came from the backend, check the network tab on the google inspector and you will see the GET request"
    }

    return jsonify(response_body), 200
