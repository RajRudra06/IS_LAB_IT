# Lab 2: Advanced Symmetric Key Ciphers
# Requirements: pip install pycryptodome
# Exercises:
# 1) Encrypt "Confidential Data" using DES with key "A1B2C3D4". Then decrypt to verify.
# 2) Encrypt "Sensitive Information" using AES-128 with key "0123456789ABCDEF0123456789ABCDEF". Then decrypt.
# 3) Compare encryption/decryption times for DES and AES-256 for "Performance Testing of Encryption Algorithms".
# 4) Encrypt "Classified Text" using Triple DES (3DES) with key "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF". Then decrypt.
# 5) Encrypt "Top Secret Data" using AES-192 with key "FEDCBA9876543210FEDCBA9876543210". Show steps (we'll demonstrate key usage & operation).

from Crypto.Cipher import DES, AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import time, binascii

# Helper for printable hex
def hx(b): return binascii.hexlify(b).decode()

# Q1) DES (ECB) — key must be 8 bytes
# Note: DES is insecure; used only for lab/demo per exercise.
key_des = b"A1B2C3D4"  # 8 bytes
msg1 = b"Confidential Data"
cipher_des = DES.new(key_des, DES.MODE_ECB)
ct1 = cipher_des.encrypt(pad(msg1, DES.block_size))
pt1 = unpad(DES.new(key_des, DES.MODE_ECB).decrypt(ct1), DES.block_size)
print("# Q1 DES ciphertext (hex):", hx(ct1))
print("# Q1 DES decrypted:", pt1.decode())

# Q2) AES-128 (ECB) — key 16 bytes (128-bit). Provided key is 32-hex chars -> 16 bytes
key_aes128 = bytes.fromhex("0123456789ABCDEF0123456789ABCDEF")
msg2 = b"Sensitive Information"
cipher_aes128 = AES.new(key_aes128, AES.MODE_ECB)
ct2 = cipher_aes128.encrypt(pad(msg2, AES.block_size))
pt2 = unpad(AES.new(key_aes128, AES.MODE_ECB).decrypt(ct2), AES.block_size)
print("# Q2 AES-128 ciphertext (hex):", hx(ct2))
print("# Q2 AES-128 decrypted:", pt2.decode())

# Q3) Performance compare DES vs AES-256 on same message (ECB here for simplicity)
msg3 = b"Performance Testing of Encryption Algorithms"
# Prepare keys
key_aes256 = get_random_bytes(32)  # AES-256
key_des_local = get_random_bytes(8)
# DES timing
t0 = time.time()
denc = DES.new(key_des_local, DES.MODE_ECB).encrypt(pad(msg3, DES.block_size))
ddec = DES.new(key_des_local, DES.MODE_ECB).decrypt(denc)
t1 = time.time()
des_time = t1 - t0
# AES-256 timing
t0 = time.time()
aenc = AES.new(key_aes256, AES.MODE_ECB).encrypt(pad(msg3, AES.block_size))
adec = AES.new(key_aes256, AES.MODE_ECB).decrypt(aenc)
t1 = time.time()
aes256_time = t1 - t0
print("# Q3 DES time:", des_time, "AES-256 time:", aes256_time)

# Q4) Triple DES (3DES) — key length 16 or 24 bytes. Provided hex string is 48 hex chars -> 24 bytes
key_3des = bytes.fromhex("1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF")
msg4 = b"Classified Text"
# Create 3DES cipher (ECB)
cipher_3des = DES3.new(key_3des, DES3.MODE_ECB)
ct4 = cipher_3des.encrypt(pad(msg4, DES3.block_size))
pt4 = unpad(DES3.new(key_3des, DES3.MODE_ECB).decrypt(ct4), DES3.block_size)
print("# Q4 3DES ciphertext (hex):", hx(ct4))
print("# Q4 3DES decrypted:", pt4.decode())

# Q5) AES-192: key must be 24 bytes. Provided hex corresponds to 32 hex chars -> 16 bytes; the prompt wants AES-192 with given key.
# For demonstration we'll use the given hex twice to make 24 bytes (lab demo only). In real tasks use proper 48-hex string
given_hex = "FEDCBA9876543210FEDCBA9876543210"  # 32 hex chars (16 bytes)
key_aes192 = bytes.fromhex(given_hex) + bytes.fromhex(given_hex)[:8]  # 24 bytes (demo)
msg5 = b"Top Secret Data"
cipher_aes192 = AES.new(key_aes192, AES.MODE_ECB)
ct5 = cipher_aes192.encrypt(pad(msg5, AES.block_size))
pt5 = unpad(AES.new(key_aes192, AES.MODE_ECB).decrypt(ct5), AES.block_size)
print("# Q5 AES-192 ciphertext (hex):", hx(ct5))
print("# Q5 AES-192 decrypted:", pt5.decode())

# Additional suggestions: To test CBC/CTR modes, use AES.MODE_CBC with IV and AES.MODE_CTR with nonce.
