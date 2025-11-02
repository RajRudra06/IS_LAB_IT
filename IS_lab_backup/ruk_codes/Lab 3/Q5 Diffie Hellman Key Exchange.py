# Diffie-Hellman key exchange demo with timing
# Requires: pip install pycryptodome
# This script performs a two-party DH (Alice <-> Bob), measures times and verifies the shared key.

# import helpers from pycryptodome and Python stdlib
from Crypto.Util.number import getPrime              # generate large prime numbers
import secrets                                       # for secure random private keys
import time                                          # for high-resolution timing (perf_counter)
import hashlib                                       # for deriving a fixed-length key from the shared secret
import sys                                           # for exiting on error

# -------------------------
# Configuration
# -------------------------
# choose prime size in bits (2048 is common; smaller sizes for faster demo e.g. 1024)
PRIME_BITS = 2048                                   # change to 1024 for faster runs in classroom/demo

# -------------------------
# Helper: print ms nicely
# -------------------------
def ms(elapsed_seconds):
    # convert seconds to milliseconds (float)
    return elapsed_seconds * 1000.0

# -------------------------
# 1) Generate DH parameters (prime p and generator g)
# -------------------------
print(f"Generating a {PRIME_BITS}-bit safe-looking prime p for DH (this may take a moment)...")
t0 = time.perf_counter()                             # start timer for parameter generation
p = getPrime(PRIME_BITS)                             # generate a probable prime p of PRIME_BITS bits
# choose a simple generator; 2 is commonly used when p is safe prime or for demo purposes
g = 2
t1 = time.perf_counter()                             # end timer
param_gen_ms = ms(t1 - t0)                           # compute elapsed ms
print(f"Parameter generation done. Time: {param_gen_ms:.3f} ms")
print(f"Prime p bit-length: {p.bit_length()} bits; generator g = {g}")

# -------------------------
# 2) Each peer (Alice and Bob) generates a private key and corresponding public key
# -------------------------
# --- Alice key generation ---
t0 = time.perf_counter()                             # start timer for Alice keygen
# choose a private key a uniformly at random in range [2, p-2]
alice_private = secrets.randbelow(p-2) + 2
# compute Alice's public key A = g^a mod p
alice_public = pow(g, alice_private, p)
t1 = time.perf_counter()                             # end timer for Alice keygen
alice_keygen_ms = ms(t1 - t0)                        # elapsed ms for Alice keygen
print(f"\nAlice key generation time: {alice_keygen_ms:.6f} ms")

# --- Bob key generation ---
t0 = time.perf_counter()                             # start timer for Bob keygen
# choose a private key b uniformly at random in range [2, p-2]
bob_private = secrets.randbelow(p-2) + 2
# compute Bob's public key B = g^b mod p
bob_public = pow(g, bob_private, p)
t1 = time.perf_counter()                             # end timer for Bob keygen
bob_keygen_ms = ms(t1 - t0)                          # elapsed ms for Bob keygen
print(f"Bob key generation time: {bob_keygen_ms:.6f} ms")

# print public key sizes (hex shortened) for informational purposes
print("\nPublic keys (short hex):")
print(" Alice public A (hex, first 64 chars):", hex(alice_public)[2:66], "...")
print(" Bob   public B (hex, first 64 chars):", hex(bob_public)[2:66], "...")


# -------------------------
# 3) Key exchange: each party computes the shared secret
# -------------------------
# --- Alice computes shared = B^a mod p ---
t0 = time.perf_counter()                             # start timer for Alice shared computation
alice_shared = pow(bob_public, alice_private, p)     # Alice's computed shared secret (integer)
t1 = time.perf_counter()                             # end timer
alice_shared_ms = ms(t1 - t0)                        # ms taken for Alice's shared computation
print(f"\nAlice computed shared secret in: {alice_shared_ms:.6f} ms")

# --- Bob computes shared = A^b mod p ---
t0 = time.perf_counter()                             # start timer for Bob shared computation
bob_shared = pow(alice_public, bob_private, p)       # Bob's computed shared secret (integer)
t1 = time.perf_counter()                             # end timer
bob_shared_ms = ms(t1 - t0)                          # ms taken for Bob's shared computation
print(f"Bob computed shared secret in:   {bob_shared_ms:.6f} ms")

# -------------------------
# 4) Verify both shared secrets are equal
# -------------------------
same = (alice_shared == bob_shared)                  # boolean check
print("\nShared secrets equal?", same)
if not same:
    print("Error: shared values do not match. Aborting.")
    sys.exit(1)

# -------------------------
# 5) Derive a symmetric key from the shared secret (e.g., SHA-256 of shared integer)
# -------------------------
# convert shared integer to bytes in big-endian order
shared_int = alice_shared                             # both are same
shared_bytes = shared_int.to_bytes((shared_int.bit_length() + 7) // 8, byteorder='big')
# derive 32-byte key by hashing (SHA-256)
derived_key = hashlib.sha256(shared_bytes).digest()
# print derived key (short hex)
print("Derived symmetric key (SHA-256 of shared, hex):", derived_key.hex())

# -------------------------
# 6) Summary of timings
# -------------------------
print("\nTiming summary (milliseconds):")
print(f" Parameter generation: {param_gen_ms:.3f} ms")
print(f" Alice key generation: {alice_keygen_ms:.6f} ms")
print(f" Bob   key generation: {bob_keygen_ms:.6f} ms")
print(f" Alice shared-compute: {alice_shared_ms:.6f} ms")
print(f" Bob   shared-compute: {bob_shared_ms:.6f} ms")

# -------------------------
# 7) Optionally demonstrate a small message encrypted using derived key (AES-GCM)
#    (This is just to show the shared key can be used; requires pycryptodome AES)
# -------------------------
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad

    # sample message
    sample = b"Hello from Alice (DH-derived key test)"

    # derive AES key from derived_key (use first 32 bytes -> AES-256)
    aes_key = derived_key[:32]

    # encrypt with AES-GCM to demonstrate confidentiality and integrity
    nonce = get_random_bytes(12)                        # 12-byte nonce for GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(sample)

    # decrypt using the same derived key (simulate Bob decrypting)
    cipher2 = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    pt = cipher2.decrypt_and_verify(ct, tag)

    print("\nAES-GCM demo with derived key succeeded.")
    print(" Sample plaintext:", sample.decode())
    print(" Decrypted text:  ", pt.decode())
except Exception as e:
    # if AES not available, just skip demo (pycryptodome needed)
    print("\nAES demo skipped (pycryptodome AES required) or an error occurred:", str(e))
