import unittest
from app.modern.sha256_hash import sha256_hash
from app.modern import rsa_crypto
import tempfile
import os

class TestModernCrypto(unittest.TestCase):

    # --- SHA-256 Tests ---

    def test_sha256_known_hash(self):
        self.assertEqual(
            sha256_hash("Hello World"),
            "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e"
        )

    def test_sha256_empty_string(self):
        self.assertEqual(
            sha256_hash(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

    def test_sha256_different_inputs(self):
        h1 = sha256_hash("Test 1")
        h2 = sha256_hash("Test 2")
        self.assertNotEqual(h1, h2)

    def test_sha256_consistency(self):
        data = "Consistency check"
        h1 = sha256_hash(data)
        h2 = sha256_hash(data)
        self.assertEqual(h1, h2)

    def test_sha256_unicode_input(self):
        data = "漢字"
        expected_hash = sha256_hash(data)  # Just verify it runs without error
        self.assertIsInstance(expected_hash, str)
        self.assertEqual(len(expected_hash), 64)  # SHA-256 hex length

    # --- RSA Tests ---

    def test_rsa_encrypt_decrypt(self):
        private_key, public_key = rsa_crypto.generate_keys()
        message = "Tinotenda Chidume"
        encrypted = rsa_crypto.encrypt_text(message, public_key)
        decrypted = rsa_crypto.decrypt_text(encrypted, private_key)
        self.assertEqual(decrypted, message)

    def test_rsa_sign_and_verify(self):
        private_key, public_key = rsa_crypto.generate_keys()
        message = "Hello World"
        signature = rsa_crypto.sign_message(message, private_key)
        self.assertTrue(rsa_crypto.verify_signature(message, signature, public_key))
        self.assertFalse(rsa_crypto.verify_signature("Tampered Message", signature, public_key))

    def test_rsa_sign_and_verify_file(self):
        private_key, public_key = rsa_crypto.generate_keys()
        # Create temporary file for testing
        with tempfile.NamedTemporaryFile(delete=False) as tmp_file:
            tmp_file.write(b"This is a test file content for RSA signing.")
            tmp_file_path = tmp_file.name

        try:
            signature = rsa_crypto.sign_file(tmp_file_path, private_key)
            self.assertTrue(rsa_crypto.verify_file_signature(tmp_file_path, signature, public_key))

            # Modify file to test failed verification
            with open(tmp_file_path, "ab") as f:
                f.write(b" Tampered")
            self.assertFalse(rsa_crypto.verify_file_signature(tmp_file_path, signature, public_key))
        finally:
            os.remove(tmp_file_path)

    def test_rsa_generate_keys_type(self):
        private_key, public_key = rsa_crypto.generate_keys()
        # Keys are bytes, decode for string checks
        if isinstance(private_key, bytes):
            private_key = private_key.decode('utf-8')
        if isinstance(public_key, bytes):
            public_key = public_key.decode('utf-8')

        self.assertIsInstance(private_key, str)
        self.assertIsInstance(public_key, str)
        self.assertIn("BEGIN RSA PRIVATE KEY", private_key)
        self.assertIn("BEGIN PUBLIC KEY", public_key)

    def test_rsa_encrypt_empty_string(self):
        private_key, public_key = rsa_crypto.generate_keys()
        encrypted = rsa_crypto.encrypt_text("", public_key)
        decrypted = rsa_crypto.decrypt_text(encrypted, private_key)
        self.assertEqual(decrypted, "")

if __name__ == "__main__":
    unittest.main()
