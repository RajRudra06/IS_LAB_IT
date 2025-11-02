# Preprocessing
plaintext = "I am learning information security".replace(" ","").upper()

# --- Helper functions ---
def modinv(a,m):
    """Multiplicative inverse of a modulo m"""
    for i in range(1,m):
        if (a*i)%m==1:
            return i
    return None

# --- a) Additive Cipher ---
def additive_encrypt(pt,key):
    return ''.join(chr((ord(c)-65 + key)%26 +65) for c in pt)

def additive_decrypt(ct,key):
    return ''.join(chr((ord(c)-65 - key)%26 +65) for c in ct)

key_a = 20
ct_a = additive_encrypt(plaintext,key_a)
pt_a = additive_decrypt(ct_a,key_a)
print("Additive Cipher:")
print("Ciphertext:", ct_a)
print("Decrypted:", pt_a)

# --- b) Multiplicative Cipher ---
def multiplicative_encrypt(pt,key):
    return ''.join(chr(((ord(c)-65)*key)%26 +65) for c in pt)

def multiplicative_decrypt(ct,key):
    inv = modinv(key,26)
    if inv is None:
        return "No inverse, cannot decrypt"
    return ''.join(chr(((ord(c)-65)*inv)%26 +65) for c in ct)

key_b = 15
ct_b = multiplicative_encrypt(plaintext,key_b)
pt_b = multiplicative_decrypt(ct_b,key_b)
print("\nMultiplicative Cipher:")
print("Ciphertext:", ct_b)
print("Decrypted:", pt_b)

# --- c) Affine Cipher ---
def affine_encrypt(pt,a,b):
    return ''.join(chr(((a*(ord(c)-65)+b)%26)+65) for c in pt)

def affine_decrypt(ct,a,b):
    inv = modinv(a,26)
    if inv is None:
        return "No inverse, cannot decrypt"
    return ''.join(chr(((inv*((ord(c)-65)-b))%26)+65) for c in ct)

a_c,b_c = 15,20
ct_c = affine_encrypt(plaintext,a_c,b_c)
pt_c = affine_decrypt(ct_c,a_c,b_c)
print("\nAffine Cipher:")
print("Ciphertext:", ct_c)
print("Decrypted:", pt_c)
