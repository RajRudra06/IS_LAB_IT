from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Key and data
key = b"0123456789ABCDEF0123456789ABCDEF"[:16]  # AES-128 uses 16 bytes
data = b"Sensitive Information"

# Encrypt
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
print("Ciphertext:", ciphertext.hex())

# Decrypt
decipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)
print("Decrypted:", plaintext.decode())
