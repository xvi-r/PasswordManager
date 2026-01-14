import sys
import uuid
import os
import requests
from vault_manager import VaultManager

access_token = None

def get_refresh_token():
    with open("client/refresh_token.txt", 'r') as file:
        return file.read()

def get_device_uid():
    with open("client/device_uid.txt", 'r') as file:
        return file.read()


if not os.path.exists("client/device_uid.txt"):
    with open("client/device_uid.txt", "w") as file:
        file.write(str((uuid.uuid4())))




def signup(): #TODO replace with input later
    payload = {
        "username": "test_user",
        "email": "test_email@gmail.com",
        "password": "test_password",
        "encoded_vault": "encrypted_vault_placeholder"
        }

    response = requests.post(url="https://vault.ev4xl.space/signup", json=payload)

    print(response.json(), response.status_code)

def login(): #TODO replace with input later
    payload = {
        "username": "test_user",
        "password": "test_password",
        "device_uid": get_device_uid()
        }

    response = requests.post(url="https://vault.ev4xl.space/login", json=payload)

    data = response.json()

    if response.status_code == 401:
        print(data)
        return
    
    #Store refresh token 
    with open("client/refresh_token.txt", "w") as file:
        file.write(data.get("refresh_token"))
    
    #Store access_token in memory
    access_token = data.get("access_token")
    print(data)
    
def get_vault():
    headers = {
        "Authorization": f"Bearer {access_token}"
    }
    response = requests.get(headers=headers, url="https://vault.ev4xl.space/get_vault")
    
    print(response.json())
    
def refresh_access_token():
    global access_token 
    headers = {
        "X-Refresh-Token": get_refresh_token(),
        "X-Device-UID": get_device_uid()
    }
    
    
    response = requests.post(headers=headers, url="https://vault.ev4xl.space/refresh_access_token")
    if response.status_code == 200:
        access_token = response.json().get("access_token")
        with open("client/refresh_token.txt", "w") as file:
            file.write(response.json().get("refresh_token"))
    return(response.json())
    
    
signup()
login()
print(refresh_access_token())
#get_vault()








