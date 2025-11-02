def vigenere_encrypt(text, key):
    text, key = text.replace(" ", "").lower(), key.lower()
    result = ""
    for i, c in enumerate(text):
        result += chr(((ord(c)-97 + ord(key[i % len(key)])-97) % 26)+97)
    return result

def vigenere_decrypt(cipher, key):
    key = key.lower()
    result = ""
    for i, c in enumerate(cipher):
        result += chr(((ord(c)-97 - (ord(key[i % len(key)])-97)) % 26)+97)
    return result

msg = "thehouseisbeingsoldtonight"
key = "dollars"
cipher = vigenere_encrypt(msg, key)
print("Encrypted:", cipher)
print("Decrypted:", vigenere_decrypt(cipher, key))
