from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Step 1: Define key and message
key = b"A1B2C3D4"  # 8-byte DES key
message = b"Confidential Data"

# Step 2: Create DES cipher in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Step 3: Encrypt the message (must be padded to 8-byte blocks)
ciphertext = cipher.encrypt(pad(message, DES.block_size))
print("Ciphertext (hex):", ciphertext.hex())

# Step 4: Decrypt the ciphertext and unpad
decipher = DES.new(key, DES.MODE_ECB)
plaintext = unpad(decipher.decrypt(ciphertext), DES.block_size)
print("Decrypted message:", plaintext.decode())
