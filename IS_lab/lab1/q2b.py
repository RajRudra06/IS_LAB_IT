def autokey_encrypt(text, key):
    text = text.replace(" ", "").lower()
    full_key = [key] + [ord(c)-97 for c in text[:-1]]
    result = ""
    for i, c in enumerate(text):
        result += chr(((ord(c)-97 + full_key[i]) % 26)+97)
    return result

def autokey_decrypt(cipher, key):
    cipher = cipher.lower()
    result, curr_key = "", key
    for c in cipher:
        plain = ((ord(c)-97) - curr_key) % 26
        result += chr(plain+97)
        curr_key = plain
    return result

msg = "thehouseisbeingsoldtonight"
cipher = autokey_encrypt(msg, 7)
print("Encrypted:", cipher)
print("Decrypted:", autokey_decrypt(cipher, 7))
