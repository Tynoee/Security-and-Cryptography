import unittest
from app.classical import vigenere

class TestVigenere(unittest.TestCase):
    def test_encrypt(self):
        self.assertEqual(vigenere.vigenere_encrypt("Hello World", "cryptolab"), "Jswui Ypwzh")
        self.assertEqual(vigenere.vigenere_encrypt("JohnSmith", "key"), "TczrWcqrb")

    def test_decrypt(self):
        self.assertEqual(vigenere.vigenere_decrypt("Jswui Ypwzh", "cryptolab"), "Hello World")
        self.assertEqual(vigenere.vigenere_decrypt("TczrWcqrb", "key"), "JohnSmith")
