from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# -------------------
# Step 1: Generate ECC keypair
# -------------------
private_key = ec.generate_private_key(ec.SECP256R1())  # private key
public_key = private_key.public_key()                  # public key

# -------------------
# Step 2: Generate ephemeral key for encryption (simulate sender)
# -------------------
ephemeral_private = ec.generate_private_key(ec.SECP256R1())
ephemeral_public = ephemeral_private.public_key()

# -------------------
# Step 3: Derive shared secret using ECDH
# -------------------
shared_secret = ephemeral_private.exchange(ec.ECDH(), public_key)

# -------------------
# Step 4: Derive symmetric AES key from shared secret
# -------------------
aes_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_secret)

# -------------------
# Step 5: Encrypt the message with AES-GCM
# -------------------
message = b"Secure Transactions"
nonce = os.urandom(12)
cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(message) + encryptor.finalize()
tag = encryptor.tag

print("Ciphertext (bytes):", ciphertext)

# -------------------
# Step 6: Decrypt the message using the same shared secret
# -------------------
# Receiver derives the same shared secret using their private key
shared_secret_receiver = private_key.exchange(ec.ECDH(), ephemeral_public)
aes_key_receiver = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'handshake data'
).derive(shared_secret_receiver)

cipher_dec = Cipher(algorithms.AES(aes_key_receiver), modes.GCM(nonce, tag))
decryptor = cipher_dec.decryptor()
plaintext = decryptor.update(ciphertext) + decryptor.finalize()
print("Decrypted message:", plaintext.decode('utf-8'))
