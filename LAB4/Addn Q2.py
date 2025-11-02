#!/usr/bin/env python3
# rsa_factor_demo.py
# Demonstrates factoring a vulnerable RSA modulus and recovering private key.

import random
import math
from hashlib import sha256

# ---------- Helpers ----------
def egcd(a, b):
    if b == 0: return (1, 0, a)
    x, y, g = egcd(b, a % b)
    return (y, x - (a // b) * y, g)

def modinv(a, m):
    x, y, g = egcd(a, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m

# Pollard's Rho for factorization (good for demonstrating weak keys)
def pollards_rho(n):
    if n % 2 == 0:
        return 2
    while True:
        x = random.randrange(2, n - 1)
        y = x
        c = random.randrange(1, n - 1)
        d = 1
        while d == 1:
            x = (x * x + c) % n
            y = (y * y + c) % n
            y = (y * y + c) % n
            d = math.gcd(abs(x - y), n)
            if d == n:
                break
        if 1 < d < n:
            return d

def factor(n):
    # try small trial division first
    small_primes = [2,3,5,7,11,13,17,19,23,29,31,37,41,43,47,53,59,61,67,71,73,79,83,89,97]
    for p in small_primes:
        if n % p == 0:
            return p, n//p
    # pollard
    p = pollards_rho(n)
    q = n // p
    if p > q:
        p, q = q, p
    return p, q

# ---------- Vulnerable RSA key generation (for demo) ----------
def generate_weak_prime(bits=32):
    # generate a weak prime: small bit-length or low entropy
    while True:
        p = random.getrandbits(bits)
        p |= (1 << (bits-1)) | 1  # ensure top bit and odd
        # simple primality check (not robust) - OK for demo
        if is_probable_prime(p):
            return p

def is_probable_prime(n, k=5):
    if n < 2: return False
    # Miller-Rabin
    d = n - 1
    s = 0
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 2)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_weak_rsa(bits_p=32, bits_q=32, e=65537):
    p = generate_weak_prime(bits_p)
    q = generate_weak_prime(bits_q)
    # intentionally allow p and q to be too small or similar to illustrate vulnerability
    n = p * q
    phi = (p-1)*(q-1)
    if math.gcd(e, phi) != 1:
        # for demo, tweak until valid
        return generate_weak_rsa(bits_p, bits_q, e)
    d = modinv(e, phi)
    return {'p': p, 'q': q, 'n': n, 'e': e, 'd': d}

# ---------- RSA encrypt/decrypt ----------
def rsa_encrypt(m_bytes, pub_n, pub_e):
    m = int.from_bytes(m_bytes, 'big')
    if m >= pub_n:
        raise ValueError("message too large for modulus")
    c = pow(m, pub_e, pub_n)
    return c

def rsa_decrypt_int(c, priv_d, priv_n):
    m = pow(c, priv_d, priv_n)
    # convert back to bytes (strip leading zero if any)
    mb = m.to_bytes((m.bit_length()+7)//8, 'big') or b'\x00'
    return mb

# ---------- Demo ----------
def demo():
    print("=== Demo: vulnerable RSA key generation and factoring attack ===")
    # generate intentionally weak RSA (small primes) to show factorization is easy
    key = generate_weak_rsa(bits_p=32, bits_q=32)  # weak: 32-bit primes => 64-bit n
    print(f"Generated weak RSA modulus n (hex): {hex(key['n'])}")
    print(f"Primes (p, q) sizes: {key['p'].bit_length()} bits, {key['q'].bit_length()} bits")

    message = b"Top Secret"
    print("Original message:", message)

    ciphertext = rsa_encrypt(message, key['n'], key['e'])
    print("Ciphertext (int):", ciphertext)

    # Attacker Eve factors n
    print("\n[Eve] factoring n...")
    p_rec, q_rec = factor(key['n'])
    print(f"[Eve] found factors p={p_rec}, q={q_rec}")

    # Recompute private exponent
    phi_rec = (p_rec-1)*(q_rec-1)
    d_rec = modinv(key['e'], phi_rec)
    print(f"[Eve] computed d (hex): {hex(d_rec)}")

    # Decrypt using recovered private key
    recovered_bytes = rsa_decrypt_int(ciphertext, d_rec, key['n'])
    print("[Eve] Decrypted message:", recovered_bytes)

    assert recovered_bytes == message
    print("\nAttack successful: Eve recovered private key and decrypted message.")

if __name__ == "__main__":
    demo()
