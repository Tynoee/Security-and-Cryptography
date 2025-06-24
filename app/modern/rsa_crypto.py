from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

# Generate RSA key pair
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()       # bytes
    public_key = key.publickey().export_key()  # bytes
    return private_key, public_key

# Encrypt text using public key
def encrypt_text(text, public_key):
    key = RSA.import_key(public_key)   # public_key is bytes
    cipher = PKCS1_OAEP.new(key)
    return cipher.encrypt(text.encode())

# Decrypt ciphertext using private key
def decrypt_text(ciphertext, private_key):
    key = RSA.import_key(private_key)  # private_key is bytes
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(ciphertext).decode()

# Sign text message using private key
def sign_message(message, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

# Verify text signature using public key
def verify_signature(message, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# Sign file contents using private key
def sign_file(file_path, private_key):
    with open(file_path, 'rb') as f:
        file_data = f.read()
        key = RSA.import_key(private_key)
        h = SHA256.new(file_data)
        signature = pkcs1_15.new(key).sign(h)
        return signature

# Verify file signature using public key
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

# Sign plain text (used in API)
def sign_text(text, private_key):
    key = RSA.import_key(private_key)
    h = SHA256.new(text.encode())
    signature = pkcs1_15.new(key).sign(h)
    return signature

# Verify plain text signature (used in API)
def verify_text_signature(text, signature, public_key):
    key = RSA.import_key(public_key)
    h = SHA256.new(text.encode())
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
