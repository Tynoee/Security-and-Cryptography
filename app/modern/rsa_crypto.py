from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key  # now it's clear and consistent

def encrypt_text(text, public_key):
    key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(text.encode())

def decrypt_text(ciphertext, private_key):
    key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext).decode()

def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
    
def sign_file(file_path, private_key):
        with open(file_path, 'rb') as f:
            file_data = f.read()
            key = RSA.import_key(private_key)
            h = SHA256.new(file_data)
            signature = pkcs1_15.new(key).sign(h)
            return signature
    
def verify_file_signature(file_path, signature, public_key):
    with open(file_path, 'rb') as f:
        file_data = f.read()
        key = RSA.import_key(public_key)
        h = SHA256.new(file_data)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

