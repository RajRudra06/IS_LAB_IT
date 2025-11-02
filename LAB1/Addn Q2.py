def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ","").upper()
    key = key.upper()
    ciphertext = ""
    for i, c in enumerate(plaintext):
        k = key[i % len(key)]
        ciphertext += chr((ord(c)-65 + ord(k)-65) % 26 + 65)
    return ciphertext

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    plaintext = ""
    for i, c in enumerate(ciphertext):
        k = key[i % len(key)]
        plaintext += chr((ord(c)-65 - (ord(k)-65)) % 26 + 65)
    return plaintext

# Example usage
plaintext = "Life is full of surprises"
keyword = "HEALTH"

ciphertext = vigenere_encrypt(plaintext, keyword)
decrypted = vigenere_decrypt(ciphertext, keyword)

print("Ciphertext:", ciphertext)
print("Decrypted:", decrypted)
