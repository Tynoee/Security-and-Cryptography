import unittest
from app.classical import vigenere

class TestVigenere(unittest.TestCase):

    def test_encrypt_decrypt_hello_world(self):
        text = "Hello World"
        key = "cryptolab"
        encrypted = vigenere.vigenere_encrypt(text, key)
        decrypted = vigenere.vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_tinotenda_chidume(self):
        text = "TinotendaChidume"
        key = "cryptolab"
        encrypted = vigenere.vigenere_encrypt(text, key)
        decrypted = vigenere.vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_with_custom_key(self):
        text = "The Animal Farm - George Orwell"
        key = "key"
        encrypted = vigenere.vigenere_encrypt(text, key)
        decrypted = vigenere.vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_empty_string(self):
        text = ""
        key = "anykey"
        encrypted = vigenere.vigenere_encrypt(text, key)
        decrypted = vigenere.vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_nonalpha_characters(self):
        text = "1234!@#$%^&*()_+-=[]{}|;':,.<>/?"
        key = "cryptolab"
        encrypted = vigenere.vigenere_encrypt(text, key)
        decrypted = vigenere.vigenere_decrypt(encrypted, key)
        self.assertEqual(decrypted, text)

if __name__ == "__main__":
    unittest.main()
