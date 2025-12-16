from cryptography.fernet import Fernet
from password_generator import generate_password
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

import base64
import json
import os

key_path = r"C:\passwordmanagerkey\key.key"
salt_path = r"salt.bin"

if not os.path.exists(salt_path):
    salt = os.urandom(16)
    with open(salt_path, 'wb') as file:
        file.write(salt)
    print(f"Wrote salt to {salt_path}")
else:
    with open(salt_path, "rb") as file:
        salt = file.read()
    print(f"Salt was already created reading salt fromm {salt_path}")
    
    


kdf = PBKDF2HMAC(
    algorithm=SHA256(),
    length=32,
    salt=salt,
    iterations=200_000,
)









with open(key_path, 'rb') as file:
    key = file.read()


f = Fernet(key)


def store_password(site, email, password, key):
    global data
    password = f.encrypt(password).decode("utf-8")
    
    with open("test.json", 'r') as file:
        data = json.load(file)
        
    print(type(data["google.com"]))
    
    data.setdefault(site, {}).update({email : password})
    
    print(data)
    
    json_data = json.dumps(data, indent=4)
    
    with open("test.json", 'w') as file:
        file.write(json_data)

def get_password(site, email, key):
    
    with open("test.json", 'r') as file:
        data = json.load(file)
    
    encrypted_password = data[site].get(email)
    password = f.decrypt(encrypted_password).decode("utf-8")
    
    print(f"Site : {site}, Email : {email}, Password : {password}")
    

        






#store_password("yo2ube.com", "MAA26236SSIVE@outlook.com", b"FarCAAAZBB!?", key)
#get_password("google.com", "refractxvi@outlook.com",key)

#key = base64.urlsafe_b64encode(kdf.derive("The-Purple-Dinosaur-Eats-Computer".encode("utf-8")))


#print(key)
