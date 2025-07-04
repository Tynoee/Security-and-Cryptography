from fastapi import APIRouter
from app.classical import caesar, vigenere
from app.modern.sha256_hash import sha256_hash 

router = APIRouter()

# --- Caesar Cipher ---
@router.get("/caesar/encrypt")
def caesar_encrypt(text: str, shift: int = 3):
    return {"result": caesar.caesar_encrypt(text, shift)}

@router.get("/caesar/decrypt")
def caesar_decrypt(text: str, shift: int = 3):
    return {"result": caesar.caesar_decrypt(text, shift)}

# --- Vigenère Cipher ---
@router.get("/vigenere/encrypt")
def vigenere_encrypt(text: str, key: str = "cryptolab"):
    return {"result": vigenere.vigenere_encrypt(text, key)}

@router.get("/vigenere/decrypt")
def vigenere_decrypt(text: str, key: str = "cryptolab"):
    return {"result": vigenere.vigenere_decrypt(text, key)}

@router.get("/hash/sha256")
def hash_sha256_route(text: str):
    return {"hash": sha256_hash(text)}
