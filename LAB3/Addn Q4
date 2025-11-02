import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# --- Key Generation ---
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Serialize public key for recipient sharing
public_bytes = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)

# --- Hybrid ElGamal-like Encryption ---
def elgamal_encrypt(recipient_public_key, plaintext):
    # Generate ephemeral key
    ephemeral_private = ec.generate_private_key(ec.SECP256R1())
    ephemeral_public = ephemeral_private.public_key()

    # Compute shared secret
    shared_secret = ephemeral_private.exchange(ec.ECDH(), recipient_public_key)

    # Derive symmetric key from shared secret
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"elgamal-encryption"
    ).derive(shared_secret)

    # Encrypt using AES-256 CTR
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    # Return ephemeral public key + ciphertext + iv
    ephemeral_bytes = ephemeral_public.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    return ephemeral_bytes, iv, ciphertext

def elgamal_decrypt(private_key, ephemeral_bytes, iv, ciphertext):
    ephemeral_public = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256R1(), ephemeral_bytes
    )
    shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public)

    # Derive symmetric key
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"elgamal-encryption"
    ).derive(shared_secret)

    # Decrypt
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext

# --- Example Data ---
data_samples = [
    b"Patient record: John Doe, Blood Type O+, Diagnosis: Healthy",
    b"A" * 1024,  # 1 KB
    b"B" * 10240  # 10 KB
]

# --- Measure Performance ---
for i, data in enumerate(data_samples):
    start = time.time()
    eph_pub, iv, ct = elgamal_encrypt(public_key, data)
    enc_time = time.time() - start

    start = time.time()
    pt = elgamal_decrypt(private_key, eph_pub, iv, ct)
    dec_time = time.time() - start

    print(f"Data sample {i+1}: size={len(data)} bytes")
    print(f"Encryption time: {enc_time:.6f}s")
    print(f"Decryption time: {dec_time:.6f}s")
    print(f"Decryption correct: {pt == data}\n")
