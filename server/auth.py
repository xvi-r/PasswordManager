import jwt
import os
import time
import hmac
import hashlib
from .db import get_db
from flask import Flask, g, request, jsonify

JWT_SECRET = os.getenv("JWT_SECRET")
JWT_ALGORITHM = "HS256" #keyed hash
ACCESS_TOKEN_TTL = 15 * 60 #15 minutes

def generate_access_token(user_id):
    payload = {
        "sub": user_id,
        "iat": int(time.time()),
        "exp": int(time.time()) + ACCESS_TOKEN_TTL
    }
    
    return jwt.encode(payload=payload, key=JWT_SECRET, algorithm=JWT_ALGORITHM)

def require_access_token(f):
    def wrapper(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        
        if not auth_header:
            return jsonify({"error": "missing Authorization header"}), 401
        
        try:
            token = auth_header.split(" ")[1]
            print(f"[DEBUG] : YOUR TOKEN: {token}")
        except IndexError:
            return jsonify({"error": "invalid Authorization header"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=JWT_ALGORITHM)
            
        except jwt.ExpiredSignatureError as e:
            print("[ERROR]: ", e)
            return jsonify({"error": "expired token"}), 401
        except jwt.InvalidTokenError as e:
            print("[ERROR]: ", e)
            return jsonify({"error": "invalid token"}), 401
        
        g.user_id = payload.get("sub")
        

        return f(*args, **kwargs)
    return wrapper


def hmac_token_hash(token: str):
    print(token)
    key = os.getenv("REFRESH_TOKEN_SECRET")
    if not key:
        raise RuntimeError("REFRESH_TOKEN_SECRET not set")
    print(token)
    key_bytes = key.encode()
    print(type(token))
    token_bytes = token.encode()
    
    return hmac.new(
        key_bytes,
        token_bytes,
        hashlib.sha256
    ).hexdigest()
    
    