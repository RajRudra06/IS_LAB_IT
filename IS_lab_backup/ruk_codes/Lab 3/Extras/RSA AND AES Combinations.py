# Hybrid RSA + AES chat demo (Doctor <-> Patient)
# Requirements: pip install pycryptodome

# -------------------------
# Imports
# -------------------------
from Crypto.PublicKey import RSA                     # RSA key generation & handling
from Crypto.Cipher import PKCS1_OAEP, AES            # RSA-OAEP for key transport, AES for symmetric encryption (GCM)
from Crypto.Random import get_random_bytes           # secure random bytes for AES keys and nonces
import base64                                        # for readable ciphertext printing
import sys                                           # for exiting the program
import time                                          # optional timing (not used heavily here)
#USERINPUT#
#msg_str = input("Enter a small number (as string) to encrypt: ")
#msg_int = int(msg_str)                        # convert input to integer
## Take user input (string message)

#plaintext = input("Enter message to encrypt with AES: ").encode('utf-8')


# -------------------------
# Utility helpers
# -------------------------
def b64encode(b):
    # base64-encode bytes and return str for printing/transmission
    return base64.b64encode(b).decode('ascii')

def b64decode(s):
    # base64-decode a string back to bytes
    return base64.b64decode(s.encode('ascii'))

# -------------------------
# RSA key generation helper
# -------------------------
def generate_rsa_keypair(bits=2048):
    # generate an RSA private key object with the given bit length
    key = RSA.generate(bits)
    # return tuple (private_key_obj, public_key_obj)
    return key, key.publickey()

# -------------------------
# Hybrid encrypt function: RSA-OAEP (encrypt AES key) + AES-GCM (encrypt message)
# -------------------------
def hybrid_encrypt(plaintext: str, recipient_rsa_pub):
    # encode plaintext string to bytes (UTF-8)
    plaintext_bytes = plaintext.encode('utf-8')
    # generate a fresh random AES-256 key (32 bytes)
    aes_key = get_random_bytes(32)
    # generate a random 12-byte nonce for AES-GCM (recommended size)
    nonce = get_random_bytes(12)
    # create AES-GCM cipher object with the generated AES key and nonce
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    # encrypt the plaintext and produce authentication tag
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext_bytes)
    # encrypt the AES key with recipient RSA public key using OAEP
    rsa_cipher = PKCS1_OAEP.new(recipient_rsa_pub)
    enc_aes_key = rsa_cipher.encrypt(aes_key)
    # package everything in base64 for easy display/transmission
    package = {
        'enc_aes_key_b64': b64encode(enc_aes_key),   # RSA-encrypted AES key (base64)
        'nonce_b64': b64encode(nonce),               # AES-GCM nonce (base64)
        'tag_b64': b64encode(tag),                   # AES-GCM tag (base64)
        'ciphertext_b64': b64encode(ciphertext)      # AES-GCM ciphertext (base64)
    }
    # return the package dict
    return package

# -------------------------
# Hybrid decrypt function: RSA-OAEP (decrypt AES key) + AES-GCM (decrypt message)
# -------------------------
def hybrid_decrypt(package: dict, recipient_rsa_priv):
    # base64-decode the package fields
    enc_aes_key = b64decode(package['enc_aes_key_b64'])
    nonce = b64decode(package['nonce_b64'])
    tag = b64decode(package['tag_b64'])
    ciphertext = b64decode(package['ciphertext_b64'])
    # decrypt AES key using recipient RSA private key with OAEP
    rsa_cipher = PKCS1_OAEP.new(recipient_rsa_priv)
    aes_key = rsa_cipher.decrypt(enc_aes_key)
    # create AES-GCM cipher with derived AES key and nonce
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    # decrypt and verify tag (raises ValueError if verification fails)
    plaintext_bytes = aes_cipher.decrypt_and_verify(ciphertext, tag)
    # decode bytes to UTF-8 string and return
    return plaintext_bytes.decode('utf-8')

# -------------------------
# Demo setup: generate keys for Doctor and Patient
# -------------------------
doctor_priv, doctor_pub = generate_rsa_keypair(2048)   # Doctor RSA key pair
patient_priv, patient_pub = generate_rsa_keypair(2048) # Patient RSA key pair

# print small info about keys (not secret)
print("RSA keys generated for Doctor and Patient.")
print("Doctor public key size (bits):", doctor_pub.size_in_bits())
print("Patient public key size (bits):", patient_pub.size_in_bits())
print()

# -------------------------
# Interactive chat loop
# -------------------------
print("Hybrid RSA+AES Chat Demo — Doctor <-> Patient")
print("Type messages as: doctor: Hello or patient: I am fine")
print("Type 'quit' or Ctrl+C to exit.")
print()

while True:
    try:
        # read user input from console
        line = input("Enter (sender: message) > ").strip()
    except (EOFError, KeyboardInterrupt):
        # handle Ctrl+C / EOF gracefully
        print("\nExiting.")
        sys.exit(0)

    # ignore empty lines
    if not line:
        continue

    # allow exit commands
    if line.lower() in ('quit', 'exit'):
        print("Goodbye.")
        break

    # validate format: must contain ':'
    if ':' not in line:
        print("Invalid format. Use 'doctor: message' or 'patient: message'.")
        continue

    # parse sender and message parts
    sender_raw, msg = line.split(':', 1)
    sender = sender_raw.strip().lower()
    message_text = msg.strip()

    # identify sender and recipient keys
    if sender == 'doctor':
        sender_name = 'Doctor'
        recipient_name = 'Patient'
        recipient_pubkey = patient_pub      # patient public key used to encrypt AES key
        recipient_privkey = patient_priv    # patient private key used to decrypt
    elif sender == 'patient':
        sender_name = 'Patient'
        recipient_name = 'Doctor'
        recipient_pubkey = doctor_pub
        recipient_privkey = doctor_priv
    else:
        print("Unknown sender. Use 'doctor' or 'patient'.")
        continue

    # show plaintext (for demo visibility only)
    print(f"[{sender_name}] plaintext: {message_text}")

    # encrypt the message for recipient using hybrid scheme
    package = hybrid_encrypt(message_text, recipient_pubkey)

    # display package summary (base64 strings shortened where long)
    print(f"[{sender_name}] sending encrypted package -> (to {recipient_name}):")
    print("  enc_aes_key (b64):", package['enc_aes_key_b64'][:80] + '...')
    print("  nonce (b64):      ", package['nonce_b64'])
    print("  tag (b64):        ", package['tag_b64'])
    print("  ciphertext (b64): ", package['ciphertext_b64'][:80] + '...')
    print()

    # simulate network transfer and recipient decryption
    try:
        recovered = hybrid_decrypt(package, recipient_privkey)
        print(f"[{recipient_name}] decrypted message:", recovered)
    except ValueError:
        # authentication (tag) mismatch or wrong key
        print(f"[{recipient_name}] Decryption failed: authentication error (tampered or wrong key).")

    print()  # blank line for readability
