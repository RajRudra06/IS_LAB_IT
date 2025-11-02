from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify

# AES-256 key (32 bytes)
key = b"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"[:32]

# Data
data = b"Encryption Strength"

# Encrypt (ECB mode)
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
print("Ciphertext:", hexlify(ciphertext).decode())

# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)
print("Decrypted:", plaintext.decode())
