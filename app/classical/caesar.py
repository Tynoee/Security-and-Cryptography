def caesar_encrypt(text, shift=3, alphabet=None):
    if alphabet is None:
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    result = ''
    for char in text:
        upper_char = char.upper()
        if upper_char in alphabet:
            index = alphabet.index(upper_char)
            new_index = (index + shift) % len(alphabet)
            new_char = alphabet[new_index]
    
            result += new_char if char.isupper() else new_char.lower()
        else:
            result += char
    return result

def caesar_decrypt(cipher, shift=3, alphabet=None):
    return caesar_encrypt(cipher, -shift, alphabet)

# def caesar_encrypt(text, shift=3):
#     result = ""
#     for char in text:
#         if char.isalpha():
#             shift_base = 65 if char.isupper() else 97
#             result += chr((ord(char) - shift_base + shift) % 26 + shift_base)
#         else:
#             result += char
#     return result

# def caesar_decrypt(cipher, shift=3):
#     return caesar_encrypt(cipher, -shift)
