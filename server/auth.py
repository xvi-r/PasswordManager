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
        "sub": str(user_id),
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
    key = os.getenv("REFRESH_TOKEN_SECRET")
    if not key:
        raise RuntimeError("REFRESH_TOKEN_SECRET not set")

    key_bytes = key.encode()
    print(type(token))
    token_bytes = token.encode()
    
    return hmac.new(
        key_bytes,
        token_bytes,
        hashlib.sha256
    ).hexdigest()

def store_refresh_token(db_cursor, user_id, token, device_uid, expires_in=60*60*24*30):
    token_hash = hmac_token_hash(token)
    db_cursor.execute("""
        INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at, device_uid)
        VALUES (?, ?, ?, ?, ?)
    """, (user_id, token_hash, int(time.time()) + expires_in, int(time.time()), device_uid))
