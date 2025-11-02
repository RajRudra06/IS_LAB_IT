# paillier_sharing.py
import random, math
from Crypto.Util.number import getPrime, inverse

def L(u, n): return (u - 1) // n

def generate_paillier(bit_length=512):
    p = getPrime(bit_length//2)
    q = getPrime(bit_length//2)
    n = p*q
    nsq = n*n
    lam = (p-1)*(q-1) // math.gcd(p-1, q-1)  # lcm
    g = n + 1
    # mu = (L(g^lam mod n^2))^{-1} mod n
    u = pow(g, lam, nsq)
    mu = inverse(L(u, n), n)
    pub = (n, g)
    priv = (lam, mu)
    return pub, priv

def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n*n
    r = random.randrange(1, n)
    while math.gcd(r, n) != 1:
        r = random.randrange(1, n)
    return (pow(g, m, nsq) * pow(r, n, nsq)) % nsq

def paillier_decrypt(pub, priv, c):
    n, g = pub
    lam, mu = priv
    nsq = n*n
    u = pow(c, lam, nsq)
    m = (L(u, n) * mu) % n
    return m

def homomorphic_add(c1, c2, pub):
    n, g = pub
    nsq = n*n
    return (c1 * c2) % nsq

if __name__ == "__main__":
    # Shared public key
    pub, priv = generate_paillier(bit_length=512)
    # Party A and Party B encrypt privately
    vA = 15
    vB = 25
    cA = paillier_encrypt(pub, vA)
    cB = paillier_encrypt(pub, vB)
    # Server computes encrypted sum without decrypting
    cSum = homomorphic_add(cA, cB, pub)
    # Private key holder decrypts the sum
    decrypted_sum = paillier_decrypt(pub, priv, cSum)
    print("values:", vA, vB)
    print("cipher A:", cA)
    print("cipher B:", cB)
    print("cipher sum:", cSum)
    print("decrypted sum:", decrypted_sum)  # expected 40
