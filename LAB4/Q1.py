# Requirements: pip install pycryptodome

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# -----------------------------
# Utility functions
# -----------------------------

# RSA Key generation
def generate_rsa_keypair(bits=2048):
    key = RSA.generate(bits)
    return key, key.publickey()

# RSA encrypt/decrypt small symmetric AES key
def rsa_encrypt_key(aes_key, rsa_pub):
    cipher = PKCS1_OAEP.new(rsa_pub)
    return cipher.encrypt(aes_key)

def rsa_decrypt_key(enc_key, rsa_priv):
    cipher = PKCS1_OAEP.new(rsa_priv)
    return cipher.decrypt(enc_key)

# AES-GCM encrypt/decrypt messages
def aes_encrypt(message_bytes, aes_key):
    nonce = get_random_bytes(12)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(message_bytes)
    return nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, aes_key):
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def b64encode(b): return base64.b64encode(b).decode('utf-8')
def b64decode(s): return base64.b64decode(s.encode('utf-8'))

# -----------------------------
# Diffie-Hellman (modular exponent)
# -----------------------------
def dh_generate_private(p):
    from random import randint
    return randint(2, p-2)

def dh_compute_public(g, private, p):
    return pow(g, private, p)

def dh_compute_shared(pub_other, priv_self, p):
    return pow(pub_other, priv_self, p)

# -----------------------------
# Enterprise Subsystems Setup
# -----------------------------
systems = ["Finance", "HR", "SupplyChain"]

# RSA keys for each subsystem
rsa_keys = {s: generate_rsa_keypair() for s in systems}

# Example Diffie-Hellman parameters
dh_p = 7919       # prime
dh_g = 2          # generator

# DH private/public for each subsystem
dh_keys = {}
for s in systems:
    priv = dh_generate_private(dh_p)
    pub = dh_compute_public(dh_g, priv, dh_p)
    dh_keys[s] = {'private': priv, 'public': pub}

# -----------------------------
# Secure message sending
# -----------------------------
def send_message(sender, receiver, message):
    print(f"\n[{sender} -> {receiver}] Original Message: {message}")
    
    # Generate session AES key
    aes_key = get_random_bytes(32)
    
    # Encrypt AES key with receiver's RSA public key
    enc_aes_key = rsa_encrypt_key(aes_key, rsa_keys[receiver][1])
    
    # Encrypt message with AES-GCM
    nonce, ciphertext, tag = aes_encrypt(message.encode('utf-8'), aes_key)
    
    # Package to send (all base64 for safe transmission)
    package = {
        'enc_aes_key': b64encode(enc_aes_key),
        'nonce': b64encode(nonce),
        'tag': b64encode(tag),
        'ciphertext': b64encode(ciphertext)
    }
    
    # Receiver decrypts AES key
    aes_key_received = rsa_decrypt_key(b64decode(package['enc_aes_key']), rsa_keys[receiver][0])
    
    # Decrypt message
    decrypted = aes_decrypt(
        b64decode(package['nonce']),
        b64decode(package['ciphertext']),
        b64decode(package['tag']),
        aes_key_received
    ).decode('utf-8')
    
    print(f"[{receiver}] Decrypted Message: {decrypted}")

# -----------------------------
# Demo communication
# -----------------------------
send_message("Finance", "HR", "Quarterly payroll report attached.")
send_message("HR", "SupplyChain", "New vendor contract signed.")
send_message("SupplyChain", "Finance", "Procurement order #123 ready for approval.")
