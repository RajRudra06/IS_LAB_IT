from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
import time

# -------------------
# Step 1: Generate DH parameters (shared by all peers)
# -------------------
start = time.time()
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
param_time = time.time() - start
print("DH parameters generation time:", param_time, "seconds")

# -------------------
# Step 2: Each peer generates private/public key
# -------------------
start = time.time()
peer1_private = parameters.generate_private_key()
peer1_public = peer1_private.public_key()

peer2_private = parameters.generate_private_key()
peer2_public = peer2_private.public_key()
keygen_time = time.time() - start
print("DH key generation time per peer:", keygen_time, "seconds")

# -------------------
# Step 3: Each peer computes shared secret
# -------------------
start = time.time()
shared_secret1 = peer1_private.exchange(peer2_public)
shared_secret2 = peer2_private.exchange(peer1_public)
exchange_time = time.time() - start
print("DH shared secret computation time:", exchange_time, "seconds")

# -------------------
# Step 4: Derive AES key from shared secret (optional)
# -------------------
aes_key1 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'p2p file sharing key'
).derive(shared_secret1)

aes_key2 = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,
    info=b'p2p file sharing key'
).derive(shared_secret2)

# Verify both peers derived the same key
assert aes_key1 == aes_key2
print("Shared AES key established successfully.")
