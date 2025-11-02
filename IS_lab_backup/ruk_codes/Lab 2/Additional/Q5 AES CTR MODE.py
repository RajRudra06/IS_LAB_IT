# Q4: AES CTR encryption/decryption (nonce provided)
# pip install pycryptodome

from Crypto.Cipher import AES                              # AES cipher
from Crypto.Util.Padding import pad, unpad                  # padding helpers if needed (CTR is stream-like)
# CTR mode is stream-based; padding isn't strictly required, but we can encrypt raw bytes

# plaintext, key and nonce as specified
plaintext = "Cryptography Lab Exercise"                     # plaintext
key_str = "0123456789ABCDEF0123456789ABCDEF"                # 32-char key -> AES-256
nonce_hex = "0000000000000000"                              # 16 hex chars -> 8-byte nonce (all zero)

# prepare bytes
key_bytes = key_str.encode('utf-8')                         # 32 bytes key for AES-256
nonce_bytes = bytes.fromhex(nonce_hex)                      # nonce for CTR (8 bytes)

# create AES cipher in CTR mode with given nonce
cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce_bytes) # CTR cipher instance

# encrypt plaintext bytes (CTR is stream so no padding needed)
ciphertext = cipher.encrypt(plaintext.encode('utf-8'))      # ciphertext bytes

# print ciphertext hex
print("AES-CTR Ciphertext (hex):", ciphertext.hex())

# decrypt: create a new AES CTR cipher with same key and nonce (fresh counter)
dec_cipher = AES.new(key_bytes, AES.MODE_CTR, nonce=nonce_bytes)
decrypted_bytes = dec_cipher.decrypt(ciphertext)           # decrypt (same as encrypt in CTR)
print("AES-CTR Decrypted message:", decrypted_bytes.decode('utf-8'))
