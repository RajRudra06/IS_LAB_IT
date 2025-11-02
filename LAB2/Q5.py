from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Step 1: Prepare 24-byte AES-192 key
key = bytes.fromhex("FEDCBA9876543210FEDCBA9876543210") + bytes.fromhex("FEDCBA9876543210")  # 24 bytes
data = b"Top Secret Data"

# Step 2: Encrypt
cipher = AES.new(key, AES.MODE_ECB)
ciphertext = cipher.encrypt(pad(data, AES.block_size))
print("Ciphertext:", ciphertext.hex())

# Step 3: Decrypt
decipher = AES.new(key, AES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), AES.block_size)
print("Decrypted:", plaintext.decode())
