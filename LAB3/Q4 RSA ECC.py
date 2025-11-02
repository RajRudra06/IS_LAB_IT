import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes

# --- Key Generation ---
start = time.time()
rsa_key = RSA.generate(2048)
rsa_pub = rsa_key.publickey()
end = time.time()
print("RSA key generation time:", end - start, "seconds")

# --- File Encryption ---
def rsa_encrypt_file(filename):
    # Read file
    with open(filename, 'rb') as f:
        data = f.read()

    # Generate AES key for hybrid encryption
    aes_key = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    # Encrypt AES key with RSA
    cipher_rsa = PKCS1_OAEP.new(rsa_pub)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    return enc_aes_key, cipher_aes.nonce, tag, ciphertext

# --- File Decryption ---
def rsa_decrypt_file(enc_aes_key, nonce, tag, ciphertext):
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return data

# ECC Implementation (secp256r1) 

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# --- ECC Key Generation ---
start = time.time()
ecc_priv = ec.generate_private_key(ec.SECP256R1())
ecc_pub = ecc_priv.public_key()
end = time.time()
print("ECC key generation time:", end - start, "seconds")

# --- File Encryption ---
def ecc_encrypt_file(filename, receiver_pub):
    with open(filename, 'rb') as f:
        data = f.read()

    # Ephemeral key for hybrid encryption
    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key()
    shared_secret = eph_priv.exchange(ec.ECDH(), receiver_pub)

    # Derive AES key
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file encryption'
    ).derive(shared_secret)

    # AES-GCM encryption
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag

    return eph_pub, nonce, tag, ciphertext

# --- File Decryption ---
def ecc_decrypt_file(eph_pub, nonce, tag, ciphertext, priv_key):
    shared_secret = priv_key.exchange(ec.ECDH(), eph_pub)
    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'file encryption'
    ).derive(shared_secret)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag))
    decryptor = cipher.decryptor()
    data = decryptor.update(ciphertext) + decryptor.finalize()
    return data

# performance measurement 

import os

# Example: files of 1MB, 10MB
for size in [1*1024*1024, 10*1024*1024]:
    test_file = f'test_{size}.bin'
    with open(test_file, 'wb') as f:
        f.write(os.urandom(size))  # random content

    # Measure RSA encryption/decryption
    start = time.time()
    enc_aes_key, nonce, tag, ciphertext = rsa_encrypt_file(test_file)
    rsa_enc_time = time.time() - start

    start = time.time()
    decrypted_data = rsa_decrypt_file(enc_aes_key, nonce, tag, ciphertext)
    rsa_dec_time = time.time() - start

    print(f"RSA: File size {size} bytes -> enc: {rsa_enc_time:.4f}s, dec: {rsa_dec_time:.4f}s")

    # Measure ECC encryption/decryption
    start = time.time()
    eph_pub, nonce, tag, ciphertext = ecc_encrypt_file(test_file, ecc_pub)
    ecc_enc_time = time.time() - start

    start = time.time()
    decrypted_data = ecc_decrypt_file(eph_pub, nonce, tag, ciphertext, ecc_priv)
    ecc_dec_time = time.time() - start

    print(f"ECC: File size {size} bytes -> enc: {ecc_enc_time:.4f}s, dec: {ecc_dec_time:.4f}s")
