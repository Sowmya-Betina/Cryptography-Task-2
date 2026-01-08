%%writefile keys.py
from Cryptodome.PublicKey import RSA
from Cryptodome.Hash import SHA256
import os

def generate_key_pair(username):

    key = RSA.generate(2048)

    
    # Export Private Key
    with open(f"{username}_private.pem", "wb") as f:
        f.write(key.export_key()) # converts to byte string format

    # Reference from PyCryptodome RSA documentaion https://pycryptodome.readthedocs.io/en/latest/src/public_key/rsa.html
    # Export Public Key
    public_key = key.publickey().export_key() # seperates public key from private part
    with open(f"{username}_public.pem", "wb") as f:
        f.write(public_key)

    key_hash = SHA256.new(public_key).hexdigest() #creates hash fingerprint to identify the key
    return public_key, key_hash

def load_public_key(username):
    with open(f"{username}_public.pem", "rb") as f:
        return RSA.import_key(f.read()) # converts back to RSA object


def load_private_key(username):
  with open(f"{username}_private.pem", "rb") as f:
    return RSA.import_key(f.read())


if __name__ == "__main__":
    print("Key Generation")
    for user in ["Alice", "Bob"]:
        generate_key_pair(user)
        print(f"Generated keys for {user}")
