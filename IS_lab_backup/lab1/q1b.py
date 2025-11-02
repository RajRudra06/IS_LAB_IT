from math import gcd

def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def multiplicative_encrypt(text, key):
    return "".join([chr(((ord(c)-97)*key) % 26 + 97) for c in text.lower().replace(" ", "")])

def multiplicative_decrypt(cipher, key):
    inv = mod_inverse(key, 26)
    return "".join([chr(((ord(c)-97)*inv) % 26 + 97) for c in cipher])

msg = "Iamlearninginformationsecurity"
key = 15
cipher = multiplicative_encrypt(msg, key)
print("Encrypted:", cipher)
print("Decrypted:", multiplicative_decrypt(cipher, key))
