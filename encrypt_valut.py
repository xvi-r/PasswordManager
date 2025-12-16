import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
import base64


salt_path = r"salt.bin"

with open(salt_path, "rb") as file:
        salt = file.read()

kdf = PBKDF2HMAC(
    algorithm=SHA256(),
    length=32,
    salt=salt,
    iterations=200_000,
)


plaintext = "test123".encode("utf-8")
key = base64.urlsafe_b64encode(kdf.derive(plaintext))
print(key)
f = Fernet(key)

with open("vault.json", 'r') as file:
    data = file.read()


data = data.encode("utf-8")


encrypted_vault = f.encrypt(data)

with open("vault.bin", 'wb') as file:
    file.write(base64.urlsafe_b64decode(encrypted_vault))

decrypt = f.decrypt(encrypted_vault)

