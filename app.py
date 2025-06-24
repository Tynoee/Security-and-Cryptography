from flask import Flask, render_template, request, jsonify
from app.modern import rsa_crypto
from app.modern.sha256_hash import sha256_hash
from app.utils.file_io import read_file
from app.classical import caesar, vigenere
from Crypto.PublicKey import RSA
import base64

app = Flask(__name__)

# Digital signature functions
def sign_text(text, private_key_pem):
    signature_bytes = rsa_crypto.sign_text(text, private_key_pem)
    return base64.b64encode(signature_bytes).decode()

def verify_signature(text, signature_b64, public_key_pem):
    signature_bytes = base64.b64decode(signature_b64)
    return rsa_crypto.verify_text_signature(text, signature_bytes, public_key_pem)

# Generate default RSA keypair for testing/demo use
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode('utf-8')
    public_key = key.publickey().export_key().decode('utf-8')
    return private_key, public_key

DEFAULT_PRIVATE_KEY, DEFAULT_PUBLIC_KEY = generate_rsa_keys()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/process', methods=['POST'])
def process():
    data = request.json
    operation = data.get('operation')

    try:
        # RSA encryption/decryption
        if operation == 'encrypt_rsa':
            text = data.get('text', '')
            public_key = data.get('public_key') or DEFAULT_PUBLIC_KEY
            encrypted_bytes = rsa_crypto.encrypt_text(text, public_key)
            result = base64.b64encode(encrypted_bytes).decode()

        elif operation == 'decrypt_rsa':
            ciphertext_b64 = data.get('text', '')
            private_key = data.get('private_key') or DEFAULT_PRIVATE_KEY
            ciphertext = base64.b64decode(ciphertext_b64)
            result = rsa_crypto.decrypt_text(ciphertext, private_key)

        # Caesar cipher
        
        elif operation == 'encrypt_caesar':
            text = data.get('text', '')
            key = data.get('classic_key')
            key = int(key) if key is not None else 3  # Default Caesar key
            result = caesar.caesar_encrypt(text, key)

        elif operation == 'decrypt_caesar':
            text = data.get('text', '')
            key = data.get('classic_key')
            key = int(key) if key is not None else 3  # Default Caesar key
            result = caesar.caesar_decrypt(text, key)


        # Vigenère cipher
        elif operation == 'encrypt_vigenere':
            text = data.get('text', '')
            key = data.get('classic_key')
            if not key:
                return jsonify({'error': 'Key required for Vigenère cipher'}), 400
            result = vigenere.vigenere_encrypt(text, key)

        elif operation == 'decrypt_vigenere':
            text = data.get('text', '')
            key = data.get('classic_key')
            if not key:
                return jsonify({'error': 'Key required for Vigenère cipher'}), 400
            result = vigenere.vigenere_decrypt(text, key)

        # SHA-256 hashing
        elif operation == 'hash':
            text = data.get('text', '')
            result = sha256_hash(text)

        # Digital signature
        elif operation == 'sign_file':
            file_content = data.get('file_content', '')
            private_key = data.get('private_key', DEFAULT_PRIVATE_KEY)  # Use default if none provided
            signature = sign_text(file_content, private_key)

        
        elif operation == 'verify_signature':
            file_content = data.get('file_content', '')
            signature_b64 = data.get('signature')
            public_key = data.get('public_key')
            if not all([public_key, signature_b64]):
                return jsonify({'error': 'Public key and signature required'}), 400
            verified = verify_signature(file_content, signature_b64, public_key)
            result = "Signature verified ✔️" if verified else "Signature invalid ❌"

        else:
            return jsonify({'error': 'Invalid operation'}), 400

        return jsonify({'result': result})

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
