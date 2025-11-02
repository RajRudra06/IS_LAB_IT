from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad

# Key (24 bytes = 3DES key length)
key = b"1234567890ABCDEF1234567890ABCDEF"

# Data
data = b"Classified Text"

# Encrypt
cipher = DES3.new(key, DES3.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, DES3.block_size))
print("Ciphertext:", ciphertext.hex())

# Decrypt
decipher = DES3.new(key, DES3.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), DES3.block_size)
print("Decrypted:", plaintext.decode())
