import time
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

message = b"Performance Testing of Encryption Algorithms"

# AES-256 setup
aes_key = b"0123456789ABCDEF0123456789ABCDEF"  # 32 bytes = AES-256
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

# DES setup
des_key = b"8bytekey"  # 8 bytes = DES key
des_cipher = DES.new(des_key, DES.MODE_ECB)

# --- AES-256 ---
start = time.time()
aes_ct = aes_cipher.encrypt(pad(message, AES.block_size))
aes_encrypt_time = time.time() - start

start = time.time()
aes_pt = unpad(AES.new(aes_key, AES.MODE_ECB).decrypt(aes_ct), AES.block_size)
aes_decrypt_time = time.time() - start

# --- DES ---
start = time.time()
des_ct = des_cipher.encrypt(pad(message, DES.block_size))
des_encrypt_time = time.time() - start

start = time.time()
des_pt = unpad(DES.new(des_key, DES.MODE_ECB).decrypt(des_ct), DES.block_size)
des_decrypt_time = time.time() - start

print("AES-256 Encryption Time:", aes_encrypt_time)
print("AES-256 Decryption Time:", aes_decrypt_time)
print("DES Encryption Time:", des_encrypt_time)
print("DES Decryption Time:", des_decrypt_time)
