from Crypto.Cipher import AES
from Crypto.Util import Counter
from binascii import hexlify

# AES-128 key (16 bytes)
key = b"0123456789ABCDEF0123456789ABCDEF"[:16]

# Nonce for CTR mode
nonce = b"00000000"  # 8 bytes
ctr = Counter.new(64, prefix=nonce)

# Data
data = b"Cryptography Lab Exercise"

# Encrypt
cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
ciphertext = cipher.encrypt(data)
print("Ciphertext:", hexlify(ciphertext).decode())

# Decrypt (recreate counter)
ctr2 = Counter.new(64, prefix=nonce)
decipher = AES.new(key, AES.MODE_CTR, counter=ctr2)
plaintext = decipher.decrypt(ciphertext)
print("Decrypted:", plaintext.decode())
