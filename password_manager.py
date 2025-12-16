from cryptography.fernet import Fernet, InvalidToken
from password_generator import generate_password
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

import base64
import json
import os

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

plaintext = input("Enter Master Password: ").encode("utf-8")
key = kdf.derive(plaintext)

key = base64.urlsafe_b64encode(key)


f = Fernet(key)

def decrypt_vault(key) -> dict:
    with open("vault.bin", 'rb') as file:
        encrypted_vault = base64.urlsafe_b64encode(file.read())
        encrypted_vault = f.decrypt(encrypted_vault).decode("utf-8")
    encrypted_vault = json.loads(encrypted_vault)
    return encrypted_vault

def encrypt_vault(key , encrypted_json: bytes) -> None:
    with open("vault.bin", 'wb') as file:
        print("WRITING TO VAULT")
        file.write(base64.urlsafe_b64decode(encrypted_json))
        print("SUCCESS SAVED TO VAULT")

def store_password(site, email, password, key):

    decrypted_json: dict = decrypt_vault(key)
        
    decrypted_json.setdefault(site, {}).update({email : password})
    
    encrypted_json = json.dumps(decrypted_json).encode("utf-8")
    encrypted_json = f.encrypt(encrypted_json)

    encrypt_vault(key,encrypted_json)

def get_password(site, email, key):
    
    with open("test.json", 'r') as file:
        data = json.load(file)
    
    encrypted_password = data[site].get(email)
    try:
        password = f.decrypt(encrypted_password).decode("utf-8")
        print(f"Site : {site}, Email : {email}, Password : {password}")
    except InvalidToken:
        print(f"Decryption failed: Invalid Token")
    
print(type(decrypt_vault(key)))
print(decrypt_vault(key))
        






#store_password("youtube.com", "rfracx2i@gmail.com", "AWEOMEPASS!?", key)
#get_password("google.com", "refractxvi@outlook.com",key)

#key = base64.urlsafe_b64encode(kdf.derive("The-Purple-Dinosaur-Eats-Computer".encode("utf-8")))

#get_password("google.com", "Luis@gmail.com", key)
#print(key)
