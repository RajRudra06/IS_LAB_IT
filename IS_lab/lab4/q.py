# Lab 4: Advanced Asymmetric Key Ciphers + Key Management
# Requirements: pip install pycryptodome sympy
# Exercises covered:
# - Implement RSA/ElGamal/Rabin (keygen, encrypt, decrypt minimal demos)
# - Simple key management service: generate, store, revoke keys (JSON file)
# - Rabin algorithm demonstration

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import json, os, binascii
from sympy import crt
import math

def hx(b): return binascii.hexlify(b).decode()

# Q1) RSA (demo reused)
rsa_key = RSA.generate(2048)
pub_rsa = rsa_key.publickey()
print("# Q1 RSA modulus n bits:", rsa_key.n.bit_length())

# Q2) ElGamal (already shown in Lab3). Here create a simple API for encrypt/decrypt text strings using small primes.
def small_elgamal_demo():
    bits=256
    p = getPrime(bits)
    g = 2
    x = int.from_bytes(get_random_bytes(bits//8),'big')%(p-2)+1
    h = pow(g,x,p)
    m = bytes_to_long(b"ElGamal demo")
    k = int.from_bytes(get_random_bytes(16),'big')%(p-2)+1
    c1 = pow(g,k,p); c2 = (m * pow(h,k,p))%p
    s = pow(c1,x,p); s_inv = inverse(s,p); m_r = (c2 * s_inv)%p
    return long_to_bytes(m_r).decode()

print("# Q2 ElGamal demo recovered:", small_elgamal_demo())

# Q3) Rabin cryptosystem (keygen, encrypt, decrypt possible roots)
def rabin_keygen(bits=128):
    # choose p,q such that p % 4 == 3 and q % 4 == 3
    while True:
        p = getPrime(bits)
        if p % 4 == 3: break
    while True:
        q = getPrime(bits)
        if q % 4 == 3 and q != p: break
    n = p*q
    return (n, p, q)

def rabin_encrypt(m_int, n):
    return pow(m_int, 2, n)

def rabin_decrypt(c, p, q):
    # compute square roots mod p and q
    mp = pow(c, (p+1)//4, p)
    mq = pow(c, (q+1)//4, q)
    # recombine using CRT to 4 roots
    roots = []
    # compute CRT combinations
    # use sympy.crt or implement manual
    # We'll compute the four solutions using standard formula
    n = p*q
    # find coefficients for recombining
    yp = inverse(p, q)
    yq = inverse(q, p)
    r1 = (yp*p*mq + yq*q*mp) % n
    r2 = n - r1
    r3 = (yp*p*mq - yq*q*mp) % n
    r4 = n - r3
    return {r1, r2, r3, r4}

n,p,q = rabin_keygen(128)
m = bytes_to_long(b"RabinTest")
c = rabin_encrypt(m, n)
roots = rabin_decrypt(c, p, q)
possible = [long_to_bytes(r) for r in roots if 0 < r < n]
print("# Q3 Rabin number of candidate roots:", len(roots))

# Q4) Simple Key Management Service (file-based JSON)
KM_FILE = "key_manager.json"
def km_load():
    if os.path.exists(KM_FILE):
        return json.load(open(KM_FILE))
    return {}
def km_save(data):
    json.dump(data, open(KM_FILE, "w"), indent=2)
def km_generate_rsa(name, bits=2048):
    key = RSA.generate(bits)
    entry = {
        "public": key.publickey().export_key().decode(),
        "private": key.export_key().decode(),
        "revoked": False
    }
    db = km_load()
    db[name] = entry
    km_save(db)
    return name
def km_revoke(name):
    db = km_load()
    if name in db:
        db[name]["revoked"] = True
        km_save(db)

# demos
km_generate_rsa("finance_system", 1024)  # small for demo
db = km_load()
print("# Q4 Key manager entries:", list(db.keys()))
km_revoke("finance_system")
print("# Q4 finance_system revoked?:", db["finance_system"]["revoked"])

# Q5) Demonstration: Attack on weak RSA (brief skeleton)
# (The lab asks to demonstrate attack on weak RSA — here we show factorization attack for small n)
def factor_small_n(n):
    # trial division (only for small n)
    r = []
    i = 2
    while i*i <= n:
        if n % i == 0:
            r.append(i)
            n//=i
        else:
            i+=1
    if n>1: r.append(n)
    return r

small_rsa = RSA.generate(512)
factors = factor_small_n(small_rsa.n)  # works only for tiny key sizes
print("# Q5 small RSA factorization (demo) factors:", factors)
