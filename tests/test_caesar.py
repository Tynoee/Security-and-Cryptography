import unittest
from app.classical import caesar

class TestCaesarCipher(unittest.TestCase):

    def test_encrypt_decrypt_hello_world_default_shift(self):
        text = "Hello World"
        encrypted = caesar.caesar_encrypt(text)  # default shift = 3
        decrypted = caesar.caesar_decrypt(encrypted)
        self.assertEqual(decrypted, text)

    def test_encrypt_decrypt_tinotenda_chidume_custom_shift(self):
        text = "TinotendaChidume"
        shift = 5
        encrypted = caesar.caesar_encrypt(text, shift)
        decrypted = caesar.caesar_decrypt(encrypted, shift)
        self.assertEqual(decrypted, text)

