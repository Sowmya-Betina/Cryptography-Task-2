%%writefile encrypt.py
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pss
from secrets import token_bytes
from keys import load_public_key, load_private_key

def encrypt_and_sign(filepath, sender, recipient, output_file="encrypted_file"):
    # Read File
    with open(filepath, 'rb') as f:
        plaintext = f.read()

    # Symmetric Encryption AES-GCM
    # Structure reference from Lab 4 - AES code structure
    aes_key = token_bytes(32) # 256-bit key
    aes_cipher = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext) # tag - tamper seal
    nonce = aes_cipher.nonce
  

    # Asymmetric Key Protection
    recipient_pub = load_public_key(recipient)
    rsa_cipher = PKCS1_OAEP.new(recipient_pub) # RSA OAEP padding using recipient public key
    enc_aes_key = rsa_cipher.encrypt(aes_key) # recipient key to lock AES key

    # Digital Signature Sign the Ciphertext + Nonce
    sender_priv = load_private_key(sender)
    hash_obj = SHA256.new(ciphertext + nonce + tag) # bundles package into hash fro signing 
    signature = pss.new(sender_priv).sign(hash_obj) # sender private key to sign

    # Save Package [EncKeyLen(4b) EncKey Nonce(16b) Tag(16b) Sig(256b) Ciphertext]
    with open(output_file, 'wb') as f:
        f.write(len(enc_aes_key).to_bytes(4, 'big'))
        f.write(enc_aes_key)
        f.write(nonce)
        f.write(tag)
        f.write(signature)
        f.write(ciphertext)

    print(f"File encrypted and signed by {sender} for {recipient}.")
    return output_file

if __name__ == "__main__":
    encrypt_and_sign("my_files/file.py", "Alice", "Bob")
