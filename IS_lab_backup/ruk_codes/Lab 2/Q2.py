# import AES and padding helpers from pycryptodome
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Step 1: define message and key
message = b"Sensitive Information"   # plaintext in bytes
key_str = "0123456789ABCDEF0123456789ABCDEF"  # given key (32 chars)
key = key_str[:16].encode()          # take first 16 chars for AES-128

# Step 2: create AES cipher object (ECB mode for simplicity)
cipher = AES.new(key, AES.MODE_ECB)

# Step 3: pad the message to a multiple of 16 bytes (AES block size = 16)
padded_message = pad(message, 16)

# Step 4: encrypt the message
ciphertext = cipher.encrypt(padded_message)

# Step 5: print ciphertext in hex
print("Ciphertext (hex):", ciphertext.hex())

# Step 6: decrypt the ciphertext
decrypted = cipher.decrypt(ciphertext)

# Step 7: unpad and decode back to string
decrypted_message = unpad(decrypted, 16).decode()

# Step 8: print the decrypted message
print("Decrypted message:", decrypted_message)
