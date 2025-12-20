import json

data = {"accounts": {"email": "password"}}

data = json.dumps(data, indent=4)

with open("vault.json", "w") as file:
    file.write(data)