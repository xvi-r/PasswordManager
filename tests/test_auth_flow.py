import os
import sqlite3
import pytest
from server.secure_server_vault import app
from server.db import init_db


client = app.test_client()

@pytest.fixture(autouse=True)
def clean_test_db():
    db_path = "test_users.db"
    if os.path.exists(db_path):
        os.remove(db_path)
    
    init_db()

def test_signup_creates_valid_user():
    payload = {
        "username": "test_user",
        "email": "test_email@gmail.com",
        "password": "test_password",
        "encoded_vault": "encrypted_vault_placeholder"
        }
    
    response = client.post("/signup", json=payload)
    assert response.status_code == 201
    
    with sqlite3.connect(os.getenv("DATABASE")) as con:
        cursor = con.cursor()
    
        result = cursor.execute("""SELECT * FROM users WHERE email = ?""", (payload.get("email"),))
        user = result.fetchone()
    
    #Valid user will contain 5 rows, all are non-nullable
    id, username, email, password_hash, encoded_vault = user
    assert id is not None
    assert username == payload["username"]
    assert email == payload["email"]
    assert password_hash != "" 
    assert encoded_vault == payload["encoded_vault"].encode()

    
   
def test_auth_flow():

    
    payload = {
        "username": "test_user",
        "email": "test_email@gmail.com",
        "password": "test_password",
        "encoded_vault": "encrypted_vault_placeholder"
        }
    
    #/signup
    response = client.post("/signup", json=payload)
    assert response.status_code == 201
    
    
    #/login
    payload = {
    "username": "test_user",
    "password": "test_password",
    "device_uid": "test_device_uid"
    }
    response = client.post("/login", json=payload)
    assert response.status_code == 200
    access_token = response.json.get("access_token")
    assert access_token != ""

    
    #/get_vault
    headers = {"Authorization": f"Bearer {access_token}"}
    response = client.get("/get_vault", headers=headers)
    assert response.status_code == 200
    assert "vault" in response.json and response.json.get("vault") != ""
    
    
    
