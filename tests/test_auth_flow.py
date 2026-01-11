
from server.secure_server_vault import app
from server.db import init_db

init_db()
client = app.test_client()
   
def test_auth_flow():
    payload = {
        "username": "test_user",
        "email": "test_email@gmail.com",
        "password": "test_password",
        "encoded_vault": "encrypted_vault_placeholder"
        }
    
    #signup
    response = client.post("/signup", json=payload)
    assert response.status_code == 201
    
    #login
    payload = {
    "username": "test_user",
    "password": "test_password",
    "device_uid": "test_device_uid"
    }
    response = client.post("/login", json=payload)
    assert response.status_code == 200
    
    
