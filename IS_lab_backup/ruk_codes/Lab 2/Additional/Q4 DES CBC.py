# Q3: DES CBC encrypt/decrypt using fixed key and IV strings (ASCII)
# pip install pycryptodome

from Crypto.Cipher import DES                              # DES cipher
from Crypto.Util.Padding import pad, unpad                  # PKCS#7 padding

# plaintext, key and IV as specified (ASCII strings)
plaintext = "Secure Communication"                          # message to encrypt
key_str = "A1B2C3D4"                                        # 8 char key for DES (ASCII)
iv_str = "12345678"                                         # 8 char IV for CBC (ASCII)

# convert key and IV to bytes
key_bytes = key_str.encode('utf-8')                         # 8 bytes
iv_bytes = iv_str.encode('utf-8')                           # 8 bytes

# create DES cipher in CBC mode with provided IV
cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)         # DES CBC cipher

# pad plaintext to DES block size (8) and encrypt
padded = pad(plaintext.encode('utf-8'), DES.block_size)     # padded plaintext bytes
ciphertext = cipher.encrypt(padded)                         # ciphertext bytes

# print ciphertext hex for readability
print("DES-CBC Ciphertext (hex):", ciphertext.hex())

# decrypt: create new cipher instance with same key & IV for decryption
dec_cipher = DES.new(key_bytes, DES.MODE_CBC, iv_bytes)     # DES CBC decryptor
dec_padded = dec_cipher.decrypt(ciphertext)                 # decrypted padded bytes

# unpad to recover original plaintext
decrypted = unpad(dec_padded, DES.block_size).decode('utf-8')
print("DES-CBC Decrypted message:", decrypted)
