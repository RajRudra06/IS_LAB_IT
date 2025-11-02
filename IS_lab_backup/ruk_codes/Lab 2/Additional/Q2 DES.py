# Q1 fixed: DES ECB encrypt/decrypt for given hex blocks (handles non-aligned lengths)
# Requires: pip install pycryptodome

from Crypto.Cipher import DES                 # DES cipher
from Crypto.Util.Padding import pad, unpad     # PKCS#7 padding helpers
import binascii                                # helper for hex printing

# ---------------------------
# Input: key and the two plaintext blocks (hex strings)
# Replace the block hex strings below with the exact hex given in your question.
# ---------------------------
key_hex = "A1B2C3D4E5F60708"                    # key as hex (16 hex chars -> 8 bytes)
block1_hex = "54686973206973206120636f6e74656e7465"  # example hex (replace with your block1 hex)
block2_hex = "416e6f7468657220626c6f636b2068657265"  # example hex (replace with your block2 hex)

# ---------------------------
# Prepare key and data bytes
# ---------------------------
key = bytes.fromhex(key_hex)                     # convert key hex to 8 bytes (DES key)
b1 = bytes.fromhex(block1_hex)                   # convert block1 hex to bytes
b2 = bytes.fromhex(block2_hex)                   # convert block2 hex to bytes

# ---------------------------
# Helper: encrypt a single bytes object using DES-ECB.
# If its length is a multiple of 8, encrypt block-by-block without padding.
# Otherwise pad with PKCS#7 to multiple of 8, encrypt, and return padded ciphertext and flag.
# Returns (ciphertext_bytes, used_padding_flag)
# ---------------------------
def des_ecb_encrypt(data_bytes, key_bytes):
    cipher = DES.new(key_bytes, DES.MODE_ECB)    # create DES ECB cipher
    if len(data_bytes) % DES.block_size == 0:    # already block-aligned
        # encrypt each 8-byte block and concatenate results
        ct = b"".join(cipher.encrypt(data_bytes[i:i+8]) for i in range(0, len(data_bytes), 8))
        return ct, False                         # False => no padding used
    else:
        # pad to block size and encrypt whole padded buffer
        padded = pad(data_bytes, DES.block_size) # PKCS#7 padding
        ct = cipher.encrypt(padded)              # encrypt padded bytes
        return ct, True                          # True => padding was used

# ---------------------------
# Helper: decrypt ciphertext produced by des_ecb_encrypt
# If padded_flag is True, unpad after decrypting; otherwise decrypt blockwise and return bytes.
# ---------------------------
def des_ecb_decrypt(ciphertext_bytes, key_bytes, padded_flag):
    cipher = DES.new(key_bytes, DES.MODE_ECB)    # DES ECB cipher for decryption
    pt = b"".join(cipher.decrypt(ciphertext_bytes[i:i+8]) for i in range(0, len(ciphertext_bytes), 8))
    if padded_flag:
        # remove PKCS#7 padding and return
        return unpad(pt, DES.block_size)
    else:
        # no padding was used; return raw plaintext bytes
        return pt

# ---------------------------
# Encrypt block1
# ---------------------------
ct1, padded1 = des_ecb_encrypt(b1, key)        # encrypt block1, record if padding used
print("Block1 plaintext (hex):", b1.hex())      # print original hex
print("Block1 padded used? :", padded1)        # show if padding was applied
print("Block1 ciphertext (hex):", ct1.hex())   # print ciphertext hex

# Decrypt block1 to verify
pt1 = des_ecb_decrypt(ct1, key, padded1)       # decrypt and unpad if needed
print("Block1 decrypted (hex):", pt1.hex())     # should match original b1.hex()

# If plaintext represents ASCII text, optionally print it
try:
    print("Block1 decrypted (ASCII):", pt1.decode('utf-8'))
except Exception:
    pass

# ---------------------------
# Encrypt block2
# ---------------------------
ct2, padded2 = des_ecb_encrypt(b2, key)        # encrypt block2
print("\nBlock2 plaintext (hex):", b2.hex())   # print original hex
print("Block2 padded used? :", padded2)        # show if padding was applied
print("Block2 ciphertext (hex):", ct2.hex())   # print ciphertext hex

# Decrypt block2 to verify
pt2 = des_ecb_decrypt(ct2, key, padded2)       # decrypt and unpad if needed
print("Block2 decrypted (hex):", pt2.hex())     # should match original b2.hex()

# Optionally show ASCII if valid
try:
    print("Block2 decrypted (ASCII):", pt2.decode('utf-8'))
except Exception:
    pass
