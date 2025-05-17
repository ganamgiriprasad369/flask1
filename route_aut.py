from textwrap import wrap
from flask import Blueprint, jsonify, request;
from werkzeug.security import generate_password_hash, check_password_hash;
from dotenv import load_dotenv;
from flask_cors import CORS;
from pymongo import MongoClient;
import os, jwt, datetime;
from bson import ObjectId;
from functools import wraps;

load_dotenv()  

auth = Blueprint('auth',__name__)
CORS(auth)

client = MongoClient(os.getenv('MONGODB_URL'))
db=client.get_database('auther')
users=db.users 

screte_key=os.getenv('SCRETE_KEY')


@auth.route('/register', methods=["POST"])
def Register():
    data = request.json
    if users.find_one({"email":data["email"]}):
        return jsonify({"error":"Email already exist"}),404
    
    hash_pwd = generate_password_hash(data["password"])

    users.insert_one({
        "username": data["username"],
        "email":data["email"],
        "password":hash_pwd
    })
    return jsonify({"message":"user created successfully"}),201


@auth.route('/login', methods=["POST"])
def Login():
    data = request.json
    user = users.find_one({"email":data["email"]})
    if user and check_password_hash(user["password"], data["password"]):
        token = jwt.encode({
            "user_id":str(user["_id"]),
            "username":user["username"],
            "exp":datetime.datetime.utcnow() + datetime.timedelta(days=7)
        }, screte_key, algorithm="HS256")
        return jsonify({"token": token, "username": user["username"]})

    return jsonify({"error":"Invalid credentials"}),401

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'Authorization' in request.headers:
            bearer = request.headers['Authorization']  
            token = bearer.split(" ")[1] if " " in bearer else bearer

        if not token:
            return jsonify({'message': 'Token is missing!'}), 403

        try:
            decoded = jwt.decode(token, screte_key, algorithms=['HS256'])
            user_id = decoded.get("user_id")
            print("Decoded user_id:", user_id)
            current_user = users.find_one({"_id": ObjectId(user_id)})    
            if not current_user:
                return jsonify({'message': 'User not found!'}), 403
            
        except jwt.ExpiredSignatureError:
            return jsonify({'message': 'Token expired!'}), 403
        
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 403
        
        return f(current_user, *args, **kwargs)
    
    return decorated  

@auth.route('/profile', methods=["GET"])
@token_required
def profile(current_user):
    return jsonify({
        "username": current_user["username"],
        "email": current_user["email"]
    }), 200