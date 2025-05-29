def generate_key(text, key):
    key = key.upper()
    key_stream = []
    key_index = 0
    for char in text:
        if char.isalpha():
            key_stream.append(key[key_index % len(key)])
            key_index += 1
        else:
            key_stream.append(char)
    return "".join(key_stream)

def vigenere_encrypt(text, key="cryptolab"):
    key = generate_key(text, key)
    cipher_text = ""
    for i in range(len(text)):
        if text[i].isalpha():
            shift_base = 65 if text[i].isupper() else 97
            shift = ord(key[i]) - 65
            cipher_text += chr((ord(text[i]) - shift_base + shift) % 26 + shift_base)
        else:
            cipher_text += text[i]
    return cipher_text

def vigenere_decrypt(cipher, key="cryptolab"):
    key = generate_key(cipher, key)
    orig_text = ""
    for i in range(len(cipher)):
        if cipher[i].isalpha():
            shift_base = 65 if cipher[i].isupper() else 97
            shift = ord(key[i]) - 65
            orig_text += chr((ord(cipher[i]) - shift_base - shift + 26) % 26 + shift_base)
        else:
            orig_text += cipher[i]
    return orig_text

# def generate_key(text, key):
#     key = list(key)
#     if len(text) == len(key):
#         return "".join(key)
#     else:
#         for i in range(len(text) - len(key)):
#             key.append(key[i % len(key)])
#     return "".join(key)

# def vigenere_encrypt(text, key):
#     key = generate_key(text, key)
#     cipher_text = ""
#     for i in range(len(text)):
#         if text[i].isalpha():
#             shift_base = 65 if text[i].isupper() else 97
#             shift = ord(key[i].upper()) - 65
#             cipher_text += chr((ord(text[i]) - shift_base + shift) % 26 + shift_base)
#         else:
#             cipher_text += text[i]
#     return cipher_text

# def vigenere_decrypt(cipher, key):
#     key = generate_key(cipher, key)
#     orig_text = ""
#     for i in range(len(cipher)):
#         if cipher[i].isalpha():
#             shift_base = 65 if cipher[i].isupper() else 97
#             shift = ord(key[i].upper()) - 65
#             orig_text += chr((ord(cipher[i]) - shift_base - shift + 26) % 26 + shift_base)
#         else:
#             orig_text += cipher[i]
#     return orig_text
