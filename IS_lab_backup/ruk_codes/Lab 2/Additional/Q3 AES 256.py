# Q2: AES-256 encryption/decryption (ECB), every line commented
# pip install pycryptodome

from Crypto.Cipher import AES                          # AES cipher
from Crypto.Util.Padding import pad, unpad              # PKCS#7 padding

# plaintext and key strings as given
plaintext = "Encryption Strength"                       # plaintext to encrypt
key_str = "0123456789ABCDEF0123456789ABCDEF"            # 32-char key -> 32 bytes for AES-256

# convert key string to bytes (utf-8)
key_bytes = key_str.encode('utf-8')                     # 32 bytes key for AES-256

# create AES cipher in ECB mode (no IV)
cipher = AES.new(key_bytes, AES.MODE_ECB)               # AES-256 ECB cipher

# pad plaintext to AES block size (16)
padded = pad(plaintext.encode('utf-8'), AES.block_size)  # padded plaintext bytes

# encrypt padded plaintext
ciphertext = cipher.encrypt(padded)                      # ciphertext bytes

# print ciphertext in hex for readability
print("AES-256 Ciphertext (hex):", ciphertext.hex())

# decrypt: create a new AES object with same key (or reuse)
dec_cipher = AES.new(key_bytes, AES.MODE_ECB)            # AES decrypt cipher
decrypted_padded = dec_cipher.decrypt(ciphertext)        # decrypted padded bytes

# unpad and decode to string to retrieve original message
decrypted = unpad(decrypted_padded, AES.block_size).decode('utf-8')  # original plaintext
print("AES-256 Decrypted message:", decrypted)
