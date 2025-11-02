# elgamal_homomorphic.py
# Simple ElGamal demo showing multiplicative homomorphism.
import random
from Crypto.Util.number import getPrime, inverse

def generate_keypair(bits=256):
    # generate safe p (prime) and generator g = 2 (simple)
    p = getPrime(bits)
    g = 2
    # private key x, public key y = g^x mod p
    x = random.randrange(2, p-1)
    y = pow(g, x, p)
    pub = (p, g, y)
    priv = x
    return pub, priv

def encrypt(pub, m):
    p, g, y = pub
    assert 0 <= m < p
    r = random.randrange(2, p-1)
    a = pow(g, r, p)
    b = (m * pow(y, r, p)) % p
    return (a, b)

def decrypt(pub, priv, cipher):
    p, g, y = pub
    a, b = cipher
    s = pow(a, priv, p)
    m = (b * inverse(s, p)) % p
    return m

def homomorphic_multiply(c1, c2, pub):
    p, g, y = pub
    a1, b1 = c1
    a2, b2 = c2
    # component-wise multiply mod p
    return ((a1 * a2) % p, (b1 * b2) % p)

if __name__ == "__main__":
    pub, priv = generate_keypair(bits=256)
    a = 7
    b = 3
    c_a = encrypt(pub, a)
    c_b = encrypt(pub, b)
    c_prod = homomorphic_multiply(c_a, c_b, pub)
    dec_prod = decrypt(pub, priv, c_prod)
    print("a,b:", a, b)
    print("cipher a:", c_a)
    print("cipher b:", c_b)
    print("cipher a*b:", c_prod)
    print("decrypted product:", dec_prod)  # should be 21


# Enc(a)×Enc(b)=Enc(a×b) in elgamal
    
# The code implements **ElGamal encryption**, which allows multiplying encrypted numbers without decryption.
# It encrypts 7 and 3, multiplies their ciphertexts, and decrypts the result to get **21**, proving multiplicative homomorphism.
# Internally, ciphertexts ((g^r, m·y^r)) multiply component-wise so that decryption yields the product of the original plaintexts.
