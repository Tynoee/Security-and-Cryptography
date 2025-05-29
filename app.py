from flask import Flask, request, jsonify
from app.modern.rsa_crypto import encrypt_text, decrypt_text, generate_keys, sign_message, verify_signature
from app.modern.sha256_hash import sha256_hash
import base64

app = Flask(__name__)

@app.route('/hash', methods=['POST'])
def hash_text():
    data = request.get_json()
    text = data.get('text', '')
    hashed = sha256_hash(text)
    return jsonify({'hash': hashed})


@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    text = data.get('text', '')
    public_key = data.get('public_key', '')
    try:
        encrypted = encrypt_text(text, public_key)
        return jsonify({'ciphertext': base64.b64encode(encrypted).decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    ciphertext = base64.b64decode(data.get('ciphertext', ''))
    private_key = data.get('private_key', '')
    try:
        decrypted = decrypt_text(ciphertext, private_key)
        return jsonify({'plaintext': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/sign', methods=['POST'])
def sign():
    data = request.get_json()
    message = data.get('message', '')
    private_key = data.get('private_key', '')
    try:
        signature = sign_message(message, private_key)
        return jsonify({'signature': base64.b64encode(signature).decode()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


@app.route('/verify', methods=['POST'])
def verify():
    data = request.get_json()
    message = data.get('message', '')
    public_key = data.get('public_key', '')
    signature = base64.b64decode(data.get('signature', ''))
    try:
        valid = verify_signature(message, signature, public_key)
        return jsonify({'valid': valid})
    except Exception as e:
        return jsonify({'error': str(e)}), 400


if __name__ == '__main__':
    app.run(debug=True)
