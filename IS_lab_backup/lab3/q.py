# Lab 3: Asymmetric Key Ciphers
# Requirements: pip install pycryptodome
# Exercises:
# 1) Using RSA, encrypt "Asymmetric Encryption" with (n,e) then decrypt with (n,d).
# 2) Using ECC (Elliptic Curve), encrypt "Secure Transactions" with public key then decrypt (we'll perform ECIES-like hybrid encryption).
# 3) Given an ElGamal public key (p,g,h) and private x, encrypt "Confidential Data" and decrypt it.
# 4) Design secure file transfer using RSA (2048) and ECC (secp256r1) — here we provide a simple hybrid demo.
# 5) Implement Diffie-Hellman key exchange demo.

from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import os, json, binascii

def hx(b): return binascii.hexlify(b).decode()

# Q1) RSA encrypt/decrypt
key_rsa = RSA.generate(2048)
pub_rsa = key_rsa.publickey()
msg1 = b"Asymmetric Encryption"
cipher_rsa = PKCS1_OAEP.new(pub_rsa)
ct_rsa = cipher_rsa.encrypt(msg1)
pt_rsa = PKCS1_OAEP.new(key_rsa).decrypt(ct_rsa)
print("# Q1 RSA decrypted:", pt_rsa.decode())

# Q2) ECC: ECIES-like hybrid encryption
# Generate ECC key pair
ecc_key = ECC.generate(curve='P-256')
pub_ecc = ecc_key.public_key()
msg2 = b"Secure Transactions"
# ECIES pattern: generate ephemeral ECDH, derive symmetric key, encrypt with AES
# Derive shared secret using ECDH-like scalar mult with ephemeral key and receiver's pub point
def ecc_encrypt(pub_key, plaintext):
    eph = ECC.generate(curve='P-256')
    # compute shared secret: scalar multiplication: eph.d * pub_key.pointQ
    shared_point = pub_key.pointQ * eph.d
    shared_x = int(shared_point.x)
    # derive AES key from shared_x
    aes_key = SHA256.new(long_to_bytes(shared_x)).digest()[:16]
    cipher = AES.new(aes_key, AES.MODE_ECB)
    ct = cipher.encrypt(pad(plaintext, AES.block_size))
    return eph.public_key().export_key(format='DER'), ct

def ecc_decrypt(priv_key, eph_pub_der, ct):
    eph_pub = ECC.import_key(eph_pub_der)
    shared_point = eph_pub.pointQ * priv_key.d
    shared_x = int(shared_point.x)
    aes_key = SHA256.new(long_to_bytes(shared_x)).digest()[:16]
    pt = unpad(AES.new(aes_key, AES.MODE_ECB).decrypt(ct), AES.block_size)
    return pt

eph_pub_der, ct2 = ecc_encrypt(pub_ecc, msg2)
pt2 = ecc_decrypt(ecc_key, eph_pub_der, ct2)
print("# Q2 ECC decrypted:", pt2.decode())

# Q3) ElGamal (simple modular implementation)
# Keygen: pick a prime p, generator g, private x, public h = g^x mod p
def elgamal_keygen(bits=256):
    p = getPrime(bits)
    g = 2
    x = int.from_bytes(get_random_bytes(bits//8), 'big') % (p-2) + 1
    h = pow(g, x, p)
    return (p,g,h), x

def elgamal_encrypt(pub, plaintext_int):
    p,g,h = pub
    k = int.from_bytes(get_random_bytes(16), 'big') % (p-2) + 1
    c1 = pow(g, k, p)
    c2 = (plaintext_int * pow(h, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(priv, pub, cipher):
    p,g,h = pub
    x = priv
    c1, c2 = cipher
    s = pow(c1, x, p)
    s_inv = inverse(s, p)
    m = (c2 * s_inv) % p
    return m

pub_elg, priv_elg = elgamal_keygen(256)
m_int = bytes_to_long(b"Confidential Data")
c_elg = elgamal_encrypt(pub_elg, m_int)
m_rec = elgamal_decrypt(priv_elg, pub_elg, c_elg)
print("# Q3 ElGamal recovered (utf8):", long_to_bytes(m_rec).decode())

# Q4) Hybrid file transfer demo (RSA for key wrap + AES for file)
# Generate AES key, encrypt file bytes, encrypt AES key with RSA public key, then decrypt.
aes_key = get_random_bytes(32)
file_bytes = b"Example file content for secure transfer."
cipher_aes = AES.new(aes_key, AES.MODE_ECB)
ct_file = cipher_aes.encrypt(pad(file_bytes, AES.block_size))
# wrap key with RSA
wrapped_key = PKCS1_OAEP.new(pub_rsa).encrypt(aes_key)
# unwrap:
aes_key_unwrapped = PKCS1_OAEP.new(key_rsa).decrypt(wrapped_key)
pt_file = unpad(AES.new(aes_key_unwrapped, AES.MODE_ECB).decrypt(ct_file), AES.block_size)
print("# Q4 Hybrid file transfer OK:", pt_file.decode())

# Q5) Diffie-Hellman (modular) demo
# small demo: both parties agree on p,g
p = getPrime(256)
g = 2
a = int.from_bytes(get_random_bytes(32),'big') % (p-2) + 1
b = int.from_bytes(get_random_bytes(32),'big') % (p-2) + 1
A = pow(g,a,p)
B = pow(g,b,p)
shared1 = pow(B,a,p)
shared2 = pow(A,b,p)
print("# Q5 DH shared equal?:", shared1 == shared2)
