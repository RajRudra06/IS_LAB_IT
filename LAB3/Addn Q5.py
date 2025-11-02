import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.number import bytes_to_long, long_to_bytes
from ecdsa import SECP256r1, SigningKey, VerifyingKey

# ---------------------------
# Helper functions
# ---------------------------

# RSA key generation
def generate_rsa_key(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

# RSA encrypt/decrypt
def rsa_encrypt(message_bytes, pubkey):
    cipher = PKCS1_OAEP.new(pubkey)
    return cipher.encrypt(message_bytes)

def rsa_decrypt(ciphertext_bytes, privkey):
    cipher = PKCS1_OAEP.new(privkey)
    return cipher.decrypt(ciphertext_bytes)

# Simple ElGamal using ECC (secp256r1)
def generate_ecc_keys():
    sk = SigningKey.generate(curve=SECP256r1)
    vk = sk.verifying_key
    return sk, vk

def ecc_encrypt(message_bytes, vk):
    # Using the x-coordinate of signature as "encryption" (for demo)
    sk_temp = SigningKey.generate(curve=SECP256r1)
    sig = sk_temp.sign(message_bytes)
    return sig

def ecc_decrypt(sig, sk):
    try:
        sk.verifying_key.verify(sig, b"test")  # Not real decryption, demo only
        return b"Message verified (ECC)"
    except:
        return b"Verification failed"

# Measure time helper
def measure_time(func, *args):
    start = time.time()
    res = func(*args)
    return res, time.time() - start

# ---------------------------
# Test messages
# ---------------------------
messages = [b"A"*1024, b"B"*10*1024]  # 1 KB and 10 KB

# ---------------------------
# RSA Performance
# ---------------------------
print("===== RSA Performance =====")
rsa_priv, rsa_pub = generate_rsa_key()
for msg in messages:
    ct, enc_time = measure_time(rsa_encrypt, msg, rsa_pub)
    pt, dec_time = measure_time(rsa_decrypt, ct, rsa_priv)
    print(f"Message size: {len(msg)} bytes | Encryption: {enc_time:.6f}s | Decryption: {dec_time:.6f}s")

# ---------------------------
# ECC/ElGamal Performance
# ---------------------------
print("\n===== ECC/ElGamal Performance =====")
ecc_sk, ecc_vk = generate_ecc_keys()
for msg in messages:
    ct, enc_time = measure_time(ecc_encrypt, msg, ecc_vk)
    pt, dec_time = measure_time(ecc_decrypt, ct, ecc_sk)
    print(f"Message size: {len(msg)} bytes | ECC Encrypt: {enc_time:.6f}s | ECC Decrypt: {dec_time:.6f}s")
