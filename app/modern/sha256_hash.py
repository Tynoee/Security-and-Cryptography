import hashlib

def sha256_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()
