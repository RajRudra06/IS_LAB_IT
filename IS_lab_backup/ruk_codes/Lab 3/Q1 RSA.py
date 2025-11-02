# RSA Encryption and Decryption Example
# pip install pycryptodome

from Crypto.PublicKey import RSA                # for RSA key generation
from Crypto.Cipher import PKCS1_OAEP            # RSA cipher with OAEP padding

# Step 1: Generate RSA key pair (public and private)
key = RSA.generate(2048)                        # generate 2048-bit RSA key
public_key = key.publickey()                    # extract public key
private_key = key                               # private key is the original

# Step 2: Print modulus (n), public exponent (e), private exponent (d)
print("Public key (n):", public_key.n)          # modulus n
print("Public key (e):", public_key.e)          # public exponent e
print("Private key (d):", private_key.d)        # private exponent d
print()

# Step 3: Define the plaintext message
message = "Asymmetric Encryption"               # message to encrypt
print("Original Message:", message)

# Step 4: Encrypt using public key (n, e)
cipher_rsa = PKCS1_OAEP.new(public_key)         # RSA cipher with OAEP padding
ciphertext = cipher_rsa.encrypt(message.encode('utf-8'))
print("Ciphertext (hex):", ciphertext.hex())    # show ciphertext in hex

# Step 5: Decrypt using private key (n, d)
decipher_rsa = PKCS1_OAEP.new(private_key)      # RSA cipher for decryption
decrypted = decipher_rsa.decrypt(ciphertext)    # decrypt ciphertext
print("Decrypted Message:", decrypted.decode('utf-8'))
