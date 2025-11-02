# import Triple DES (DES3) and padding helpers
from Crypto.Cipher import DES3                     # Triple DES cipher
from Crypto.Util.Padding import pad, unpad         # for PKCS#7 padding

# Step 1: define the plaintext
message = b"Classified Text"                       # plaintext in bytes

# Step 2: define the key
key_str = "1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"  # given key string
key = key_str[:24].encode()                        # use first 24 bytes for 3DES

# Step 3: create Triple DES cipher object (ECB mode for simplicity)
cipher = DES3.new(key, DES3.MODE_ECB)              # create 3DES cipher in ECB mode

# Step 4: pad the plaintext to match block size (8 bytes for DES/3DES)
padded_message = pad(message, DES3.block_size)     # pad plaintext

# Step 5: encrypt the message
ciphertext = cipher.encrypt(padded_message)        # encrypt padded message

# Step 6: print ciphertext (in hex for readability)
print("Ciphertext (hex):", ciphertext.hex())

# Step 7: decrypt the ciphertext
decrypted = cipher.decrypt(ciphertext)             # decrypt ciphertext
decrypted_message = unpad(decrypted, DES3.block_size).decode()  # remove padding & decode

# Step 8: print the decrypted message
print("Decrypted message:", decrypted_message)
