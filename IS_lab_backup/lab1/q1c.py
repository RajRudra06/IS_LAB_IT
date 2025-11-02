def affine_encrypt(text, a, b):
    return "".join([chr(((a*(ord(c)-97)+b) % 26)+97) for c in text.lower().replace(" ", "")])

def affine_decrypt(cipher, a, b):
    inv_a = mod_inverse(a, 26)
    return "".join([chr(((inv_a*((ord(c)-97)-b)) % 26)+97) for c in cipher])

msg = "Iamlearninginformationsecurity"
a, b = 15, 20
cipher = affine_encrypt(msg, a, b)
print("Encrypted:", cipher)
print("Decrypted:", affine_decrypt(cipher, a, b))
