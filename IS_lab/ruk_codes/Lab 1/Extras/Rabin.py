"""
Rabin encryption demo that ensures the plaintext integer < n and recovers the original message.

This script:
- Adds a short prefix to the plaintext so the correct root can be recognized after decryption.
- Generates primes p and q with p ≡ q ≡ 3 (mod 4).
- Ensures n = p * q > m (plaintext integer).
- Encrypts: c = m^2 mod n.
- Decrypts: computes the four square roots and selects the one whose recovered plaintext starts with the prefix.
"""

import random                                 # for random bit generation
from sympy import isprime                      # primality test (sympy)
import math                                    # for bit-length calculations

# ------------------------
# Helpers
# ------------------------
def generate_prime_congruent_3_mod_4(bits):
    # generate a prime of 'bits' size with p % 4 == 3 (required for simple Rabin root algorithm)
    while True:
        candidate = random.getrandbits(bits) | (1 << (bits - 1)) | 1
        # ensure candidate is odd and has full bit-length
        if candidate % 4 != 3:
            candidate += (3 - candidate % 4)  # adjust to make ≡ 3 (mod 4), quick fix
        if isprime(candidate) and candidate % 4 == 3:
            return candidate

def rabin_keygen_for_message_length(m_int, min_bits=512):
    """
    Generate p,q such that p%4==q%4==3 and n = p*q > m_int.
    min_bits is a lower bound for p and q bit-length; increased if necessary.
    """
    # compute required bit-length for n to be > m_int
    needed_bits_for_n = m_int.bit_length() + 1
    # split between p and q
    bits_each = max(min_bits, (needed_bits_for_n + 1) // 2)
    while True:
        p = generate_prime_congruent_3_mod_4(bits_each)
        q = generate_prime_congruent_3_mod_4(bits_each)
        # avoid p == q
        if p == q:
            continue
        n = p * q
        if n > m_int:
            return n, (p, q)
        # if n is still too small, increase bit size and retry
        bits_each += 16

def rabin_encrypt(m_int, n):
    # Rabin encryption: c = m^2 mod n
    return pow(m_int, 2, n)

def rabin_decrypt_all_roots(c, p, q):
    """
    Compute four square roots of c modulo n = p*q.
    Uses the property p ≡ q ≡ 3 (mod 4) to compute roots mod p and q,
    then combines via CRT to get four roots modulo n.
    """
    # compute square roots modulo p and q (since p ≡ 3 (mod 4))
    r_p = pow(c, (p + 1) // 4, p)
    r_q = pow(c, (q + 1) // 4, q)
    # the other roots are negatives modulo p and q
    roots_p = (r_p, (-r_p) % p)
    roots_q = (r_q, (-r_q) % q)

    n = p * q
    # precompute inverses for CRT
    q_inv_mod_p = pow(q, -1, p)
    p_inv_mod_q = pow(p, -1, q)

    candidates = []
    # combine each pair (rp, rq) into a root modulo n using CRT
    for rp in roots_p:
        for rq in roots_q:
            # CRT recombination:
            # m = rp * q * (q^{-1} mod p) + rq * p * (p^{-1} mod q)  (mod n)
            m = (rp * q * q_inv_mod_p + rq * p * p_inv_mod_q) % n
            candidates.append(m)
    # return the list of 4 candidate integers
    return candidates

# ------------------------
# Demo: encrypt "Top secret data"
# ------------------------
if __name__ == "__main__":
    plaintext = "Top secret data"                  # original message string
    # add short fixed prefix to recognize correct candidate after decryption
    prefix = b"MSG:"                               # short ASCII prefix
    pt_bytes = prefix + plaintext.encode('utf-8')  # prefixed message bytes
    # convert to integer
    m_int = int.from_bytes(pt_bytes, 'big')

    print("Original plaintext:", plaintext)
    print("Prefixed plaintext bytes (hex):", pt_bytes.hex())
    print("Plaintext as integer (bit-length):", m_int.bit_length())

    # generate Rabin keys (p, q) ensuring n > m_int
    print("Generating Rabin primes (this may take a moment for large messages)...")
    n, (p, q) = rabin_keygen_for_message_length(m_int, min_bits=512)  # 512-bit primes minimum
    print(f"Generated p and q with bit lengths: p={p.bit_length()} q={q.bit_length()}")
    print("Rabin modulus n bit-length:", n.bit_length())

    # Encrypt
    c = rabin_encrypt(m_int, n)
    print("Ciphertext (integer):", c)

    # Decrypt (get 4 candidates)
    candidates = rabin_decrypt_all_roots(c, p, q)
    print("Decryption candidates (integers):", candidates)

    # try to convert each candidate back to bytes and look for prefix
    recovered = None
    for cand in candidates:
        # convert integer to bytes of appropriate length
        try:
            # compute required byte length (at least 1)
            length = max(1, (cand.bit_length() + 7) // 8)
            cand_bytes = cand.to_bytes(length, 'big')
            # check prefix
            if cand_bytes.startswith(prefix):
                # strip prefix and decode remaining bytes
                recovered = cand_bytes[len(prefix):].decode('utf-8', errors='ignore')
                print("✅ Matching candidate found.")
                print("Recovered bytes (hex):", cand_bytes.hex())
                print("Recovered plaintext:", recovered)
                break
        except OverflowError:
            # skip impossible conversions
            continue

    if recovered is None:
        print("No candidate matched the prefix. Decryption ambiguous or wrong parameters.")
