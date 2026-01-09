%%writefile decrypt.py
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.Signature import pss
from Cryptodome.PublicKey import RSA
from keys import load_public_key, load_private_key

def decrypt_and_verify(input_file, recipient, sender, output_file="recovered_file.py"):
    # Unpack the components
    with open(input_file, 'rb') as f:
        key_len = int.from_bytes(f.read(4), 'big') 
        aes_key = f.read(key_len)
        nonce = f.read(16)
        tag = f.read(16)
        signature = f.read(256)
        ciphertext = f.read()

    #  Verify Digital Signature
    sender_pub = load_public_key(sender)
    hash_obj = SHA256.new(ciphertext + nonce + tag) #signature cover every piece of encrypted package
    pss.new(sender_pub).verify(hash_obj, signature) # sender public key to verify signature
    print("Digital Signature Verified")

    # Reference from PyCryptodome documentation https://pycryptodome.readthedocs.io/en/latest/src/cipher/oaep.html
    # Asymmetric Key Decryption
    recipient_priv = load_private_key(recipient)
    rsa_cipher = PKCS1_OAEP.new(recipient_priv) #recover AES key with recipient private key
    aes_key = rsa_cipher.decrypt(aes_key)


    # Symmetric Decryption
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag) # decrypt data and check tag for integrity

    with open(output_file, 'wb') as f:
	    f.write(plaintext)

    print(f"File recovered as: {output_file}")
    print(f"Content: {plaintext.decode()}")


if __name__ == "__main__":
    decrypt_and_verify("encrypted_file", "Bob", "Alice")
