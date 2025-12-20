import json
import os
import base64
import string
import secrets
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256

class VaultManager:
    def __init__(self, master_password):
        self.salt_path = "salt.bin"
        self.vault_path = "vault.bin"
        self.salt = self._get_or_create_salt()
        self.symbols = '-_!?'
        
        key = self._derive_key(master_password)
        self.f = Fernet(key)
        
        self.unencrypted_vault = self.load_vault()

    def _get_or_create_salt(self):
        if not os.path.exists(self.salt_path):
            print("Generating salt")
            salt = os.urandom(16)
            with open(self.salt_path, 'wb') as f: f.write(salt)
            return salt
        with open(self.salt_path, 'rb') as f: return f.read()

    def _derive_key(self, password: str):
        kdf = PBKDF2HMAC(
            algorithm=SHA256(),
            length=32,
            salt=self.salt,
            iterations=200_000,
        )
        raw_key = kdf.derive(password.encode("utf-8"))
        return base64.urlsafe_b64encode(raw_key)

    def load_vault(self):
        if not os.path.exists("vault.bin"):
            print("Vault doesnt exist")
            print("Generating vault")
            with open("vault.bin", 'wb') as file:
                vault_structure = json.dumps({"site" : {"email": "password"}}).encode("utf-8")
                encrypted_json = self.f.encrypt(vault_structure)
                file.write(encrypted_json)
        try:
            with open(self.vault_path, 'rb') as file:
                encrypted_data = file.read()
              
            decrypted_json = self.f.decrypt(encrypted_data).decode("utf-8")
            print("Vault loaded")
            return json.loads(decrypted_json)
        except InvalidToken:
                print("INVALID TOKEN")
                
            
            

    def save_vault(self, data_dict):
        encrypted_token = self.f.encrypt(json.dumps(data_dict).encode("utf-8"))

        raw_binary = base64.urlsafe_b64decode(encrypted_token)
        with open(self.vault_path, 'wb') as file:
            file.write(raw_binary)
            
    def add_password(self, site: str, email: str, password: str) -> None:
        data: dict = self.load_vault()
        data.setdefault(site, {}).update({email: password})
        self.save_vault(data)

    def get_password(self, site: str, email: str):
        data = self.load_vault()
        try:
            return data[site].get(email, "Email not found")
        except KeyError:
            return "Site not found"

    def generate_password(self, length=24, min_digits=4,min_symbols=5):
        password = []
        
        if min_digits + min_symbols > length:
            raise ValueError("Minimum requirements exceed password length")
        
        for _ in range(min_digits):
            password.append(secrets.choice(string.digits))
        
        for _ in range(min_symbols):
            password.append(secrets.choice(self.symbols))
        
        for _ in range(length - min_digits - min_symbols):
            password.append(secrets.choice(string.ascii_letters))
        
        secrets.SystemRandom().shuffle(password)
        return ''.join(password)
    
    
