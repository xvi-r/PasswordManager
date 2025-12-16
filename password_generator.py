import string
import secrets

symbols = '!?'


def generate_password(length=24, min_digits=4,min_symbols=5):
    password = []
    
    if min_digits + min_symbols > length:
        raise ValueError("Minimum requirements exceed password length")
    

    for _ in range(min_digits):
        password.append(secrets.choice(string.digits))
    
    for _ in range(min_symbols):
        password.append(secrets.choice(symbols))
    
    for _ in range(length - min_digits - min_symbols):
        password.append(secrets.choice(string.ascii_letters))
    
    secrets.SystemRandom().shuffle(password)
    return ''.join(password)



    
