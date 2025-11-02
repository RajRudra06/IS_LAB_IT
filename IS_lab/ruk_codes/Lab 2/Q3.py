# import required libraries
from Crypto.Cipher import DES, AES                # DES and AES implementations
from Crypto.Util.Padding import pad, unpad        # padding functions
import time                                       # for high-resolution timing

# Step 1: define message
message = b"Performance Testing of Encryption Algorithms"  # plaintext in bytes

# Step 2: define keys
des_key = b"8bytekey"                             # DES requires 8-byte key
aes_key = b"0123456789ABCDEF0123456789ABCDEF"     # AES-256 requires 32-byte key

# Step 3: create cipher objects (ECB mode for simplicity)
des_cipher = DES.new(des_key, DES.MODE_ECB)       # DES cipher object
aes_cipher = AES.new(aes_key, AES.MODE_ECB)       # AES-256 cipher object

# Step 4: pad message (DES block = 8 bytes, AES block = 16 bytes)
des_padded = pad(message, DES.block_size)         # pad for DES
aes_padded = pad(message, AES.block_size)         # pad for AES

# ---------------- DES Timing ----------------
start = time.perf_counter()                       # high-res start time
des_ciphertext = des_cipher.encrypt(des_padded)   # encrypt with DES
enc_time_des = (time.perf_counter() - start) * 1000   # elapsed ms

start = time.perf_counter()                       # high-res start time
des_decrypted = unpad(des_cipher.decrypt(des_ciphertext), DES.block_size)
dec_time_des = (time.perf_counter() - start) * 1000   # elapsed ms

# ---------------- AES-256 Timing ----------------
start = time.perf_counter()                       # high-res start time
aes_ciphertext = aes_cipher.encrypt(aes_padded)   # encrypt with AES-256
enc_time_aes = (time.perf_counter() - start) * 1000   # elapsed ms

start = time.perf_counter()                       # high-res start time
aes_decrypted = unpad(aes_cipher.decrypt(aes_ciphertext), AES.block_size)
dec_time_aes = (time.perf_counter() - start) * 1000   # elapsed ms

# Step 5: print results
print("Original message:", message.decode())
print("\n--- DES Results ---")
print("Ciphertext (hex):", des_ciphertext.hex())
print("Decrypted:", des_decrypted.decode())
print(f"Encryption time: {enc_time_des:.6f} ms")
print(f"Decryption time: {dec_time_des:.6f} ms")

print("\n--- AES-256 Results ---")
print("Ciphertext (hex):", aes_ciphertext.hex())
print("Decrypted:", aes_decrypted.decode())
print(f"Encryption time: {enc_time_aes:.6f} ms")
print(f"Decryption time: {dec_time_aes:.6f} ms")
