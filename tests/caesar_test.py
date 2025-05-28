import unittest
from app.classical import caesar

class TestCaesar(unittest.TestCase):
    def test_encrypt(self):
        self.assertEqual(caesar.caesar_encrypt("Hello World", 3), "Khoor Zruog")
        self.assertEqual(caesar.caesar_encrypt("JohnSmith", 5), "OtsmXnrmy")

    def test_decrypt(self):
        self.assertEqual(caesar.caesar_decrypt("Khoor Zruog", 3), "Hello World")
        self.assertEqual(caesar.caesar_decrypt("OtsmXnrmy", 5), "JohnSmith")
