import sqlite3
import secrets
import time
import jwt
from auth import generate_access_token, require_access_token, hmac_token_hash
from db import get_db, init_db
from flask import Flask, g, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash




app = Flask(__name__)


@app.teardown_appcontext
def close_db(error):
    db = g.pop("db", None)
    if db is not None:
        db.close()

@app.route("/")
def index():
    return "Vault service is running"


@app.route("/signup", methods = ["POST"])
def signup():
    if request.method == "POST":
        data = request.get_json()

        if not data:
            return jsonify({"error": "Missing JSON body"}), 400
        
        username = data.get("username")
        email = data.get("email")
        password = data.get("password")
        vault = data.get("encoded_vault").encode("utf-8")
        
        if not username or not email or not vault or not password:
            return jsonify({"error": "missing required fields"}), 400
        
        password_hash = generate_password_hash(password)
        
        db = get_db()
        try:
            db.execute(
                """
                INSERT INTO users (username, email, password_hash, vault)
                VALUES (?, ?, ?, ?)
                """,
                (username, email, password_hash, vault)
            )
            
            db.commit()
        except sqlite3.IntegrityError:
            return jsonify({"error": "username or email already exists"}), 409

        return jsonify({"message": "User created successfully"}), 201

@app.route("/login", methods = ["POST"])
def login():
    if request.method == "POST":
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "Missing JSON body"}), 400

        username = data.get("username")
        password = data.get("password")
        device_uid = data.get("device_uid")

        if not username or not password or not device_uid:
            return jsonify({"error": "Missing required fields"}), 400
        
        db = get_db()
        cur = db.cursor()
        
        cur.execute("""SELECT id, password_hash FROM users WHERE username = ?
                   """,(username,))
        
        user = cur.fetchone()
        
        if user is None:
            return jsonify({"error": "No such user exists"}), 401
        
        cur.execute("""SELECT 1 FROM refresh_tokens WHERE user_id = ? AND device_uid = ?
                   """,(user[0], device_uid))
        
        user_device_uid = cur.fetchone()
        
        if user_device_uid:
            return jsonify({"error": "This device is already logged in"}), 401
        
        
        if check_password_hash(user[1], password):
            refresh_token = secrets.token_urlsafe(64)
            print(refresh_token)
            refresh_token_hash = hmac_token_hash(refresh_token)
            
            
            cur.execute(
                """
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at, created_at, device_uid)
                VALUES (?, ?, ?, ?, ?)
                """,
                (user[0], refresh_token_hash, int(time.time()) + 60 * 60 * 24 * 30, int(time.time()), device_uid)
            )
            db.commit()
            return jsonify({"message": "Successful token creation",
                            "refresh_token": refresh_token,
                            "access_token": generate_access_token(user[0])}), 200
            
            
            
            
            return jsonify({"message": "Connection succesfull"}), 200
        
        
        else: 
            return jsonify({"error":f"Incorrect password for user: {username}"}), 400

@app.route("/get_vault", methods = ["GET"])
@require_access_token
def get_vault():
    user_id = g.user_id
    
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute("""SELECT vault FROM users WHERE id = ?
                   """,(user_id,))
    result = cursor.fetchone()
    
    if not result:
        return jsonify({"error": "vault not found"}), 401
    vault_bytes = result[0]
    vault_str = vault_bytes.decode("utf-8")
    
    
    return jsonify({"vault": vault_str}), 200
        
        
@app.route("/refresh_access_token", methods = ["POST"])
def refresh_access_token():
    
    if request.method == "POST":
        
        refresh_token = request.headers.get("X-Refresh-Token")
        device_uid = request.headers.get("X-Device-UID")
            
        connection = get_db()
        cursor = connection.cursor()
        
        cursor.execute("""SELECT * FROM refresh_tokens WHERE token_hash = ? AND device_uid = ?""",
                    (hmac_token_hash(refresh_token), device_uid,))
        
        result = cursor.fetchone()
        
        
        if result is not None:
            sub = str(result[1])
            print(type)
            return jsonify({"access_token": generate_access_token(sub)}),200
        else:
            return jsonify({"message":"no such refresh token for this device"}), 401
        
 
    
    
    

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)
