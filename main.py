import sys
import uuid
import os
import requests
from vault_manager import VaultManager



if not os.path.exists("device_uid.txt"):
    with open("device_uid.txt", "w") as file:
        file.write(str((uuid.uuid4())))

with open("device_uid.txt", "r") as file:
    device_uid = file.read()

access_token = None

def signup(): #TODO replace with input later
    payload = {
        "username": "test_user",
        "email": "test_email@gmail.com",
        "password": "test_pass123",
        "encoded_vault": "encrypted_vault_placeholder"
        }

    response = requests.post(url="https://vault.ev4xl.space/signup", json=payload)

    print(response.json(), response.status_code)

def login(): #TODO replace with input later
    payload = {
        "username": "test_user",
        "password": "test_email@gmail.com",
        "device_uid": device_uid
        }

    response = requests.post(url="https://vault.ev4xl.space/login", json=payload)

    data = response.json()
    
    if response.status_code == 401:
        print(data)
        return
    
    #Store refresh token 
    with open("refresh_token.txt", "w") as file:
        file.write(data.get("refresh_token"))
    
    #Store access_token in memory
    access_token = data.get("access_token")
    
#signup()
login()















"""
try:
    vault_manager = VaultManager("test123")
except ValueError as e:
    print(e)
    sys.exit(1)
    


print("Password: ",vault_manager.get_password("google.com","Luis@gmail.com"))
#vault_manager.save_vault()
"""




