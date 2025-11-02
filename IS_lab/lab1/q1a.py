# def additive_cipher_encrypt(text, key):
#     result = ""
#     for char in text.replace(" ", "").lower():
#         result += chr(((ord(char) - 97 + key) % 26) + 97)
#     return result

# def additive_cipher_decrypt(cipher, key):
#     result = ""
#     for char in cipher:
#         result += chr(((ord(char) - 97 - key) % 26) + 97)
#     return result

# msg = "Iamlearninginformationsecurity"
# key = 20
# cipher = additive_cipher_encrypt(msg, key)
# print("Encrypted:", cipher)
# print("Decrypted:", additive_cipher_decrypt(cipher, key))

print("hello")