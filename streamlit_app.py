import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import base64

# --- Classic Ciphers ---

def caesar_encrypt(text, key):
    result = []
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            result.append(chr((ord(char) - offset + key) % 26 + offset))
        else:
            result.append(char)
    return ''.join(result)

def caesar_decrypt(text, key):
    return caesar_encrypt(text, -key)

def vigenere_encrypt(text, key):
    result = []
    key = key.upper()
    key_length = len(key)
    key_indices = [ord(k) - 65 for k in key]
    j = 0
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = key_indices[j % key_length]
            result.append(chr((ord(char) - offset + k) % 26 + offset))
            j += 1
        else:
            result.append(char)
    return ''.join(result)

def vigenere_decrypt(text, key):
    result = []
    key = key.upper()
    key_length = len(key)
    key_indices = [ord(k) - 65 for k in key]
    j = 0
    for char in text:
        if char.isalpha():
            offset = 65 if char.isupper() else 97
            k = key_indices[j % key_length]
            result.append(chr((ord(char) - offset - k + 26) % 26 + offset))
            j += 1
        else:
            result.append(char)
    return ''.join(result)

# --- RSA Functions ---

def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode()
    public_key = key.publickey().export_key().decode()
    return private_key, public_key

def rsa_encrypt(plaintext, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_bytes = cipher.encrypt(plaintext.encode())
    return base64.b64encode(encrypted_bytes).decode()

def rsa_decrypt(ciphertext_b64, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(ciphertext_b64)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted.decode()

def rsa_sign(text, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    h = SHA256.new(text.encode())
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()

def rsa_verify(text, signature_b64, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    h = SHA256.new(text.encode())
    signature = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def rsa_sign_file(file_bytes, private_key_pem):
    private_key = RSA.import_key(private_key_pem)
    h = SHA256.new(file_bytes)
    signature = pkcs1_15.new(private_key).sign(h)
    return base64.b64encode(signature).decode()

def rsa_verify_file(file_bytes, signature_b64, public_key_pem):
    public_key = RSA.import_key(public_key_pem)
    h = SHA256.new(file_bytes)
    signature = base64.b64decode(signature_b64)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

def sha256_hash(text):
    h = SHA256.new(text.encode())
    return h.hexdigest()

# --- Streamlit UI ---

st.title("Crypto App")

tab1, tab2, tab3, tab4 = st.tabs(["Classic Ciphers", "RSA Encryption", "Digital Signatures", "File Operations"])

with tab1:
    st.header("Caesar Cipher")
    caesar_text = st.text_area("Text to encrypt/decrypt:", "")
    caesar_key = st.number_input("Key (integer):", min_value=0, max_value=25, value=3)
    if st.button("Encrypt Caesar"):
        st.success(caesar_encrypt(caesar_text, caesar_key))
    if st.button("Decrypt Caesar"):
        st.success(caesar_decrypt(caesar_text, caesar_key))
    
    st.markdown("---")

    st.header("Vigenère Cipher")
    vigenere_text = st.text_area("Text to encrypt/decrypt (Vigenère):", "")
    vigenere_key = st.text_input("Key (alphabetic):", "")
    if vigenere_key.isalpha():
        if st.button("Encrypt Vigenère"):
            st.success(vigenere_encrypt(vigenere_text, vigenere_key))
        if st.button("Decrypt Vigenère"):
            st.success(vigenere_decrypt(vigenere_text, vigenere_key))
    else:
        st.info("Please enter an alphabetic key for Vigenère cipher.")

with tab2:
    st.header("RSA Key Generation")
    if st.button("Generate RSA Key Pair"):
        priv_key, pub_key = generate_rsa_keys()
        st.code(priv_key, language='pem')
        st.code(pub_key, language='pem')
        st.session_state['private_key'] = priv_key
        st.session_state['public_key'] = pub_key

    st.header("RSA Encryption / Decryption")
    rsa_text = st.text_area("Text to encrypt or decrypt:", "")
    
    private_key = st.text_area("Private Key (PEM):", value=st.session_state.get('private_key', ''), height=150)
    public_key = st.text_area("Public Key (PEM):", value=st.session_state.get('public_key', ''), height=150)

    action = st.radio("Operation:", ["Encrypt with Public Key", "Decrypt with Private Key"])

    if st.button("Run RSA Operation"):
        try:
            if action == "Encrypt with Public Key":
                if not public_key.strip():
                    st.error("Please provide the public key.")
                else:
                    encrypted = rsa_encrypt(rsa_text, public_key)
                    st.success("Encrypted (base64):")
                    st.code(encrypted)
            else:
                if not private_key.strip():
                    st.error("Please provide the private key.")
                else:
                    decrypted = rsa_decrypt(rsa_text, private_key)
                    st.success("Decrypted text:")
                    st.code(decrypted)
        except Exception as e:
            st.error(f"Error: {e}")

with tab3:
    st.header("Digital Signature - Sign Text")
    sign_text_input = st.text_area("Text to sign:", "")
    sign_private_key = st.text_area("Private Key (PEM) to sign with:", value=st.session_state.get('private_key', ''), height=150)

    if st.button("Sign Text"):
        try:
            if not sign_private_key.strip():
                st.error("Please provide the private key to sign.")
            else:
                signature = rsa_sign(sign_text_input, sign_private_key)
                st.success("Signature (base64):")
                st.code(signature)
                st.session_state['last_signature'] = signature
        except Exception as e:
            st.error(f"Error signing text: {e}")

    st.markdown("---")
    st.header("Verify Signature")
    verify_text = st.text_area("Text to verify:", "")
    verify_signature_b64 = st.text_area("Signature (base64):", value=st.session_state.get('last_signature', ''), height=100)
    verify_public_key = st.text_area("Public Key (PEM) to verify with:", value=st.session_state.get('public_key', ''), height=150)

    if st.button("Verify Signature"):
        try:
            if not verify_public_key.strip() or not verify_signature_b64.strip():
                st.error("Please provide public key and signature for verification.")
            else:
                valid = rsa_verify(verify_text, verify_signature_b64, verify_public_key)
                if valid:
                    st.success("Signature is VALID ✔️")
                else:
                    st.error("Signature is INVALID ❌")
        except Exception as e:
            st.error(f"Error verifying signature: {e}")

with tab4:
    st.header("SHA-256 Hash")
    hash_text = st.text_area("Enter text to hash (SHA-256):", "")
    if st.button("Compute SHA-256 Hash"):
        if hash_text:
            st.code(sha256_hash(hash_text))
        else:
            st.info("Please enter text to hash.")

    st.markdown("---")
    st.header("Sign File")
    file_to_sign = st.file_uploader("Upload file to sign:")

    # Use stored private key as default for signing file
    default_priv_key = st.session_state.get('private_key', '')

    sign_file_private_key = st.text_area(
        "Private Key (PEM) to sign file with:",
        value=default_priv_key,
        height=150
    )
    
    if st.button("Sign File"):
        if file_to_sign is None:
            st.error("Please upload a file to sign.")
        elif not sign_file_private_key.strip():
            st.error("Please provide the private key to sign the file.")
        else:
            try:
                file_bytes = file_to_sign.read()
                signature = rsa_sign_file(file_bytes, sign_file_private_key)
                st.success("File signature (base64):")
                st.code(signature)
                st.session_state['last_file_signature'] = signature
            except Exception as e:
                st.error(f"Error signing file: {e}")

    st.markdown("---")
    st.header("Verify File Signature")
    file_to_verify = st.file_uploader("Upload file to verify:")
    signature_to_verify = st.text_area("Signature (base64) to verify:", value=st.session_state.get('last_file_signature', ''), height=100)
    verify_file_public_key = st.text_area("Public Key (PEM) to verify file with:", value=st.session_state.get('public_key', ''), height=150)

    if st.button("Verify File Signature"):
        if file_to_verify is None:
            st.error("Please upload a file to verify.")
        elif not signature_to_verify.strip():
            st.error("Please provide the signature to verify.")
        elif not verify_file_public_key.strip():
            st.error("Please provide the public key to verify the file.")
        else:
            try:
                file_bytes = file_to_verify.read()
                valid = rsa_verify_file(file_bytes, signature_to_verify, verify_file_public_key)
                if valid:
                    st.success("File signature is VALID ✔️")
                else:
                    st.error("File signature is INVALID ❌")
            except Exception as e:
                st.error(f"Error verifying file signature: {e}")
