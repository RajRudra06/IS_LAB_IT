# Simple RSA + AES-GCM chat demo between Doctor and Patient
# Requirements: pip install pycryptodome

# Import cryptographic primitives and helpers
from Crypto.PublicKey import RSA                     # RSA key generation and handling
from Crypto.Cipher import PKCS1_OAEP, AES             # RSA-OAEP for key transport, AES for symmetric encryption (GCM)
from Crypto.Random import get_random_bytes            # secure random bytes for AES keys and nonces
from Crypto.Hash import SHA256                        # optional, used by PKCS1_OAEP by default (not referenced)
import base64                                         # for readable ciphertext printing
import sys                                            # for exit

# -----------------------------
# Utility functions
# -----------------------------
def generate_rsa_keypair(bits=2048):
    # Generate an RSA private key object of the given bit length and return (priv, pub)
    key = RSA.generate(bits)                          # generate RSA keypair
    return key, key.publickey()                       # return (private_key_obj, public_key_obj)

def rsa_encrypt_key(aes_key_bytes, rsa_pub):
    # Encrypt a small symmetric AES key using RSA-OAEP and return ciphertext bytes
    cipher_rsa = PKCS1_OAEP.new(rsa_pub)              # create OAEP cipher with recipient public key
    return cipher_rsa.encrypt(aes_key_bytes)          # RSA-encrypt the AES key and return bytes

def rsa_decrypt_key(enc_aes_key_bytes, rsa_priv):
    # Decrypt RSA-OAEP encrypted AES key using recipient private key and return AES key bytes
    cipher_rsa = PKCS1_OAEP.new(rsa_priv)             # create OAEP cipher with recipient private key
    return cipher_rsa.decrypt(enc_aes_key_bytes)      # decrypt and return AES key bytes

def aes_gcm_encrypt(plaintext_bytes, aes_key):
    # Encrypt plaintext (bytes) using AES-GCM with given aes_key (bytes)
    nonce = get_random_bytes(12)                      # generate 12-byte nonce for GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # create AES-GCM cipher
    ciphertext, tag = cipher.encrypt_and_digest(plaintext_bytes)  # encrypt and compute tag
    return nonce, ciphertext, tag                     # return all parts

def aes_gcm_decrypt(nonce, ciphertext, tag, aes_key):
    # Decrypt AES-GCM ciphertext and verify tag; raises ValueError if verification fails
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # create AES-GCM decryptor with same nonce
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)  # decrypt and verify tag
    return plaintext                                   # return plaintext bytes

def b64encode(b):
    # Base64-encode bytes and return a printable str (for displaying ciphertext)
    return base64.b64encode(b).decode('utf-8')

def b64decode(s):
    # Base64-decode a string back to bytes
    return base64.b64decode(s.encode('utf-8'))

# -----------------------------
# High-level message functions
# -----------------------------
def encrypt_message_for_recipient(plaintext_str, recipient_pub):
    # Hybrid encrypt: produce package where AES key is RSA-encrypted and payload is AES-GCM
    plaintext_bytes = plaintext_str.encode('utf-8')    # encode incoming string to bytes
    aes_key = get_random_bytes(32)                     # generate random 32-byte AES-256 key
    nonce, ciphertext, tag = aes_gcm_encrypt(plaintext_bytes, aes_key)  # symmetric encryption
    enc_aes_key = rsa_encrypt_key(aes_key, recipient_pub)  # encrypt AES key with recipient RSA pub
    # return a dict package with base64 parts for safe printing/transmission
    package = {
        'enc_aes_key_b64': b64encode(enc_aes_key),     # RSA-encrypted AES key (b64)
        'nonce_b64': b64encode(nonce),                 # AES-GCM nonce (b64)
        'tag_b64': b64encode(tag),                     # AES-GCM tag (b64)
        'ciphertext_b64': b64encode(ciphertext)        # AES-GCM ciphertext (b64)
    }
    return package

def decrypt_received_package(package, recipient_priv):
    # Reverse of encrypt_message_for_recipient: recover AES key with RSA and decrypt AES-GCM payload
    # base64 decode all fields
    enc_aes_key = b64decode(package['enc_aes_key_b64'])
    nonce = b64decode(package['nonce_b64'])
    tag = b64decode(package['tag_b64'])
    ciphertext = b64decode(package['ciphertext_b64'])
    # decrypt AES key with RSA private key
    aes_key = rsa_decrypt_key(enc_aes_key, recipient_priv)
    # decrypt payload with AES-GCM (may raise ValueError if tampered)
    plaintext_bytes = aes_gcm_decrypt(nonce, ciphertext, tag, aes_key)
    return plaintext_bytes.decode('utf-8')             # return decoded plaintext string

# -----------------------------
# Setup: generate keys for Doctor and Patient
# -----------------------------
doctor_priv, doctor_pub = generate_rsa_keypair(2048)    # Doctor's RSA keypair
patient_priv, patient_pub = generate_rsa_keypair(2048)  # Patient's RSA keypair

# Print fingerprint-like info to show keys generated (public modulus sizes)
print("Doctor and Patient RSA keys generated.")
print("Doctor public key size (bits):", doctor_pub.size_in_bits())
print("Patient public key size (bits):", patient_pub.size_in_bits())
print()

# -----------------------------
# Simple interactive chat loop (local demo)
# -----------------------------
print("Simple secure chat demo (Doctor <-> Patient). Type 'quit' to exit.")
print("To send a message, type the sender: 'doctor' or 'patient' and then the message.")
print("Example input: doctor: Hello, how are you?")
print()

# Loop reading user input lines
while True:
    try:
        # Prompt user for input
        line = input("Enter (sender: message) > ").strip()
    except (EOFError, KeyboardInterrupt):
        # Handle Ctrl+C / EOF gracefully by exiting the loop
        print("\nExiting chat.")
        sys.exit(0)

    # Exit command
    if not line:
        continue
    if line.lower() in ('quit', 'exit'):
        print("Goodbye.")
        break

    # Parse input of form "doctor: message" or "patient: message"
    if ':' not in line:
        print("Invalid format. Use 'doctor: message' or 'patient: message'.")
        continue

    sender_raw, msg = line.split(':', 1)                 # split into sender and message
    sender = sender_raw.strip().lower()                  # normalize sender token
    message_text = msg.strip()                           # strip whitespace from message

    # Validate sender and determine recipient and their public/private keys
    if sender == 'doctor':
        sender_name = 'Doctor'
        recipient_name = 'Patient'
        recipient_pubkey = patient_pub                   # recipient's public key (used to encrypt AES key)
        recipient_privkey = patient_priv                 # recipient's private key (used to decrypt)
    elif sender == 'patient':
        sender_name = 'Patient'
        recipient_name = 'Doctor'
        recipient_pubkey = doctor_pub
        recipient_privkey = doctor_priv
    else:
        print("Unknown sender. Use 'doctor' or 'patient'.")
        continue

    # Display the plaintext that will be encrypted (for demo only)
    print(f"[{sender_name}] plaintext: {message_text}")

    # Encrypt the message for the recipient
    package = encrypt_message_for_recipient(message_text, recipient_pubkey)

    # Display the ciphertext package (base64) that would be transmitted
    print(f"[{sender_name}] encrypted package -> (to {recipient_name}):")
    print("  enc_aes_key (b64):", package['enc_aes_key_b64'][:80] + '...')
    print("  nonce (b64):      ", package['nonce_b64'])
    print("  tag (b64):        ", package['tag_b64'])
    print("  ciphertext (b64): ", package['ciphertext_b64'][:80] + '...')
    print()

    # Simulate network delivery and immediate decryption by recipient
    try:
        recovered = decrypt_received_package(package, recipient_privkey)
        print(f"[{recipient_name}] decrypted message:", recovered)
    except ValueError:
        # This happens if authentication fails (tampered ciphertext / tag mismatch)
        print(f"[{recipient_name}] Decryption failed: authentication error (tampered or wrong key).")

    print()  # blank line for readability
