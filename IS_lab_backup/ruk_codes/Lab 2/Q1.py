# import DES from Crypto.Cipher (pycryptodome library is required)
from Crypto.Cipher import DES

# Step 1: define the message and key
message = b"Confidential Data"   # plaintext must be in bytes
key = b"A1B2C3D4"               # DES key must be exactly 8 bytes long

# Step 2: create DES cipher object (ECB mode for simplicity)
cipher = DES.new(key, DES.MODE_ECB)

# Step 3: pad message to be multiple of 8 bytes (DES block size = 8)
# if not multiple of 8, add spaces to the end
while len(message) % 8 != 0:
    message += b' '

# Step 4: encrypt the message
ciphertext = cipher.encrypt(message)

# Step 5: print ciphertext (hexadecimal format for readability)
print("Ciphertext (hex):", ciphertext.hex())

# Step 6: decrypt the ciphertext
decrypted = cipher.decrypt(ciphertext)

# Step 7: remove padding spaces and convert back to string
decrypted = decrypted.strip().decode()

# Step 8: print original decrypted message
print("Decrypted message:", decrypted)
