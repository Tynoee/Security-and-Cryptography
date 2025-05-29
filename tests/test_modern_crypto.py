import unittest
from app.modern.sha256_hash import sha256_hash
from app.modern import rsa_crypto

class TestModernCrypto(unittest.TestCase):
    
    def test_sha256(self):
        self.assertEqual(
            sha256_hash("Hello World"),
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        )
        
    def test_rsa_encrypt_decrypt(self):
        private_key, public_key = rsa_crypto.generate_keys()
        message = "Tinotenda Chidume"
        encrypted = rsa_crypto.encrypt_text(message, public_key)
        decrypted = rsa_crypto.decrypt_text(encrypted, private_key)
        self.assertEqual(decrypted, message)

    def test_digital_signature(self):
        private_key, public_key = rsa_crypto.generate_keys()
        message = "Hello World"
        signature = rsa_crypto.sign_message(message, private_key)
        self.assertTrue(rsa_crypto.verify_signature(message, signature, public_key))
        self.assertFalse(rsa_crypto.verify_signature("Tampered Message", signature, public_key))
    
    def test_file_digital_signature(self):
        file_path = "TinotendaChidume.txt"
        private_key, public_key = rsa_crypto.generate_keys()
        signature = rsa_crypto.sign_file(file_path, private_key)
        self.assertTrue(rsa_crypto.verify_file_signature(file_path, signature, public_key))
        # Tamper check
        with open(file_path, "a") as f:
            f.write(" Tampered.")
        self.assertFalse(rsa_crypto.verify_file_signature(file_path, signature, public_key))
        # Clean up
        with open(file_path, "w") as f:
            f.write("My name is Tinotenda Chidume and this file is for testing digital signatures.")
    
if __name__ == '__main__':
    unittest.main()
