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

