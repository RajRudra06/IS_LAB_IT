from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from binascii import hexlify

# Key and IV (8 bytes each for DES)
key = b"A1B2C3D4"
iv = b"12345678"

# Data
data = b"Secure Communication"

# Encrypt (CBC mode)
cipher = DES.new(key, DES.MODE_CBC, iv)
ciphertext = cipher.encrypt(pad(data, DES.block_size))
print("Ciphertext:", hexlify(ciphertext).decode())

# Decrypt
decipher = DES.new(key, DES.MODE_CBC, iv)
plaintext = unpad(decipher.decrypt(ciphertext), DES.block_size)
print("Decrypted:", plaintext.decode())
