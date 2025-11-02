# paillier_threshold_sim.py
import random
from Crypto.Util.number import getPrime, inverse
import math

# ---------- small Shamir secret sharing (mod prime)
def eval_poly(coeffs, x, p):
    res = 0
    for i, a in enumerate(coeffs):
        res = (res + a * pow(x, i, p)) % p
    return res

def shamir_split(secret, n, k, prime):
    # random polynomial degree k-1 with constant term = secret
    coeffs = [secret] + [random.randrange(0, prime) for _ in range(k-1)]
    shares = [(i, eval_poly(coeffs, i, prime)) for i in range(1, n+1)]
    return shares

def lagrange_interpolate(x, x_s, y_s, p):
    # compute f(x) from points (x_s, y_s) in mod p
    total = 0
    k = len(x_s)
    for i in range(k):
        xi, yi = x_s[i], y_s[i]
        num, den = 1, 1
        for j in range(k):
            xj = x_s[j]
            if j != i:
                num = (num * (x - xj)) % p
                den = (den * (xi - xj)) % p
        total = (total + yi * num * inverse(den, p)) % p
    return total

# ---------- Paillier (simple)
def L(u, n): 
    return (u-1)//n

def generate_paillier(bit_length=512):
    p = getPrime(bit_length//2)
    q = getPrime(bit_length//2)
    n = p*q
    nsq = n*n
    lam = (p-1)*(q-1) // math.gcd(p-1, q-1)
    g = n+1
    u = pow(g, lam, nsq)
    mu = inverse(L(u, n), n)
    return (n, g), (lam, mu)

def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n*n
    r = random.randrange(1, n)
    while math.gcd(r, n) != 1:
        r = random.randrange(1, n)
    return (pow(g,m,nsq) * pow(r, n, nsq)) % nsq

def paillier_decrypt_with_lambda(pub, lam, mu, c):
    n, g = pub
    nsq = n*n
    u = pow(c, lam, nsq)
    m = (L(u,n) * mu) % n
    return m

if __name__ == "__main__":
    # generate paillier keys
    pub, priv = generate_paillier(bit_length=512)
    lam, mu = priv
    # choose prime > lam for Shamir field
    prime = getPrime(lam.bit_length() + 1)
    assert prime > lam

    # split lambda into shares among 5 parties, threshold 3
    shares = shamir_split(lam, n=5, k=3, prime=prime)

    # Two parties encrypt values and server computes sum (as before)
    A = 12
    B = 8
    cA = paillier_encrypt(pub, A)
    cB = paillier_encrypt(pub, B)
    cSum = (cA * cB) % (pub[0]*pub[0])

    # Now reconstruct lambda from any 3 shares and decrypt
    chosen = shares[:3]  # simulate 3 parties cooperating
    x_s = [s[0] for s in chosen]
    y_s = [s[1] for s in chosen]
    lam_reconstructed = lagrange_interpolate(0, x_s, y_s, prime)  # evaluate at 0 = secret
    lam_reconstructed %= prime
    # lam_reconstructed should equal original lam mod prime. If prime>lam, then equal.
    decrypted_sum = paillier_decrypt_with_lambda(pub, lam_reconstructed, mu, cSum)
    print("A,B:", A, B)
    print("Decrypted sum via reconstruct:", decrypted_sum)
