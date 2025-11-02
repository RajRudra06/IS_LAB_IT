from Crypto.Cipher import DES
from binascii import unhexlify, hexlify

# Key (8 bytes = 64 bits for DES)
key = b"A1B2C3D4E5F60708"[:8]

# Data blocks (hex strings)
block1 = "54686973206973206120636f6e666964656e7469616c206d657373616765"
block2 = "416e64207468697320697320746865207365636f6e6420626c6f636b"

# Convert hex to bytes
data1 = unhexlify(block1)
data2 = unhexlify(block2)

# Pad to 8-byte multiple (DES block size)
def pad(data):
    pad_len = 8 - (len(data) % 8)
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

# Encrypt
cipher = DES.new(key, DES.MODE_ECB)
ct1 = cipher.encrypt(pad(data1))
ct2 = cipher.encrypt(pad(data2))

print("Ciphertext Block 1:", hexlify(ct1).decode())
print("Ciphertext Block 2:", hexlify(ct2).decode())

# Decrypt
decipher = DES.new(key, DES.MODE_ECB)
pt1 = unpad(decipher.decrypt(ct1))
pt2 = unpad(decipher.decrypt(ct2))

print("Decrypted Block 1:", pt1.decode())
print("Decrypted Block 2:", pt2.decode())
