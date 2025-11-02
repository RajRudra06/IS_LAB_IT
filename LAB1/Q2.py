# vigenere cipher
def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ","").upper()
    key = key.upper()
    ct = ""
    for i, c in enumerate(plaintext):
        k = key[i % len(key)]
        ct += chr((ord(c)-65 + ord(k)-65)%26 + 65)
    return ct

def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    pt = ""
    for i, c in enumerate(ciphertext):
        k = key[i % len(key)]
        pt += chr((ord(c)-65 - (ord(k)-65))%26 + 65)
    return pt

plaintext = "the house is being sold tonight"
vigenere_key = "dollars"

ct_v = vigenere_encrypt(plaintext, vigenere_key)
pt_v = vigenere_decrypt(ct_v, vigenere_key)

print("Vigenere Cipher:")
print("Ciphertext:", ct_v)
print("Decrypted:", pt_v)

# autokey cipher
def autokey_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ","").upper()
    ct = ""
    k = key % 26
    # first letter with initial key
    first = (ord(plaintext[0])-65 + k)%26
    ct += chr(first + 65)
    # remaining letters
    for i in range(1,len(plaintext)):
        shift = ord(plaintext[i-1]) - 65
        c = (ord(plaintext[i])-65 + shift)%26
        ct += chr(c + 65)
    return ct

def autokey_decrypt(ciphertext, key):
    ciphertext = ciphertext.replace(" ","").upper()
    pt = ""
    k = key % 26
    # first letter
    first = (ord(ciphertext[0])-65 - k)%26
    pt += chr(first + 65)
    # remaining letters
    for i in range(1,len(ciphertext)):
        shift = ord(pt[i-1])-65
        c = (ord(ciphertext[i])-65 - shift)%26
        pt += chr(c + 65)
    return pt

autokey_key = 7
ct_a = autokey_encrypt(plaintext, autokey_key)
pt_a = autokey_decrypt(ct_a, autokey_key)

print("\nAutokey Cipher:")
print("Ciphertext:", ct_a)
print("Decrypted:", pt_a)
