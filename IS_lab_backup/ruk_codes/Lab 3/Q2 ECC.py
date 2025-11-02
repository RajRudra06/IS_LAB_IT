# ECC (ECIES-like) encryption demo using pycryptodome
# pip install pycryptodome

from Crypto.PublicKey import ECC            # ECC key operations
from Crypto.Hash import SHA256              # SHA-256 to derive symmetric key
from Crypto.Cipher import AES               # AES for symmetric encryption (GCM)
from Crypto.Random import get_random_bytes  # secure random generator
import binascii                             # hex helpers

# -----------------------------
# Helpers for point serialization (we fix curve = P-256 here)
# -----------------------------
CURVE_NAME = "P-256"                         # curve used (NIST P-256)
CURVE_BYTES = 32                             # P-256 coordinates fit in 32 bytes

def point_to_bytes(point):
    # convert EccPoint-like (point.x, point.y integers) to concatenated bytes x||y (each CURVE_BYTES)
    x = int(point.x)
    y = int(point.y)
    xb = x.to_bytes(CURVE_BYTES, byteorder="big")
    yb = y.to_bytes(CURVE_BYTES, byteorder="big")
    return xb + yb

def bytes_to_point(pub_bytes):
    # convert concatenated x||y bytes back to integers and construct ECC public key
    xb = pub_bytes[:CURVE_BYTES]
    yb = pub_bytes[CURVE_BYTES:CURVE_BYTES*2]
    x = int.from_bytes(xb, byteorder="big")
    y = int.from_bytes(yb, byteorder="big")
    # construct a public ECC key object from coordinates
    return ECC.construct(point_x=x, point_y=y, curve=CURVE_NAME)

# -----------------------------
# Key generation for recipient (receiver)
# -----------------------------
recipient_key = ECC.generate(curve=CURVE_NAME)     # generate recipient ECC key pair
recipient_pub = recipient_key.public_key()         # public key to be given to senders

# Print recipient public key (PEM) and private d (for demonstration)
print("Recipient public key (PEM):")
print(recipient_pub.export_key(format="PEM"))
# (private key would normally be kept secret)
# print("Recipient private key (d):", recipient_key.d)

# -----------------------------
# Sender: encrypt function (ECIES-like)
# -----------------------------
def ecc_encrypt(plaintext_str, recipient_public_key):
    # encode plaintext to bytes
    plaintext = plaintext_str.encode("utf-8")

    # 1) generate ephemeral ECC keypair for this encryption
    eph_key = ECC.generate(curve=CURVE_NAME)            # ephemeral private key
    eph_pub = eph_key.public_key()                      # ephemeral public key

    # 2) derive shared secret: multiply recipient_pub.pointQ by eph_priv.d
    #    Shared point = recipient_pub.pointQ * eph_private.d
    shared_point = recipient_public_key.pointQ * eph_key.d

    # 3) derive symmetric key from shared_point.x using SHA-256
    shared_x = int(shared_point.x).to_bytes(CURVE_BYTES, "big")
    kdf = SHA256.new(shared_x).digest()                 # 32-byte key (use for AES-256)
    aes_key = kdf                                       # use full 32 bytes for AES-256

    # 4) encrypt plaintext using AES-GCM with a random nonce
    nonce = get_random_bytes(12)                        # 12-byte nonce recommended for GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)

    # 5) serialize ephemeral public key so recipient can reconstruct shared secret
    eph_pub_bytes = point_to_bytes(eph_pub.pointQ)     # 64 bytes for P-256 (x||y)

    # return a package containing ephemeral pub, nonce, tag, ciphertext (all bytes)
    return eph_pub_bytes, nonce, tag, ciphertext

# -----------------------------
# Recipient: decrypt function
# -----------------------------
def ecc_decrypt(eph_pub_bytes, nonce, tag, ciphertext, recipient_priv_key):
    # 1) reconstruct ephemeral public key object from bytes
    eph_pub_obj = bytes_to_point(eph_pub_bytes)         # ECC key object for ephemeral public

    # 2) derive shared secret: ephemeral_pub.pointQ * recipient_private.d
    shared_point = eph_pub_obj.pointQ * recipient_priv_key.d

    # 3) derive symmetric key from shared_point.x using SHA-256 (same as sender)
    shared_x = int(shared_point.x).to_bytes(CURVE_BYTES, "big")
    kdf = SHA256.new(shared_x).digest()
    aes_key = kdf

    # 4) decrypt with AES-GCM using nonce and verify tag
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)

    # return decoded plaintext string
    return plaintext.decode("utf-8")

# -----------------------------
# Demo: encrypt and decrypt a message
# -----------------------------
message = "Secure Transactions"                        # message to send
print("\nOriginal message:", message)

# Sender encrypts using recipient's public key
ephemeral_pub_bytes, nonce, tag, ct = ecc_encrypt(message, recipient_pub)

# Print components in hex for readability (ephemeral public key, nonce, tag, ciphertext)
print("\nEphemeral public (hex):", binascii.hexlify(ephemeral_pub_bytes).decode())
print("AES-GCM nonce (hex)     :", binascii.hexlify(nonce).decode())
print("GCM tag (hex)           :", binascii.hexlify(tag).decode())
print("Ciphertext (hex)        :", binascii.hexlify(ct).decode())

# Recipient decrypts using their private key
recovered = ecc_decrypt(ephemeral_pub_bytes, nonce, tag, ct, recipient_key)

# Show recovered plaintext
print("\nDecrypted message:", recovered)
