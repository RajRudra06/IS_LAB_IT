# ECC (ECIES-like) encryption + decryption demo using P-256 and AES-GCM
# Requires: pip install pycryptodome

from Crypto.PublicKey import ECC                  # ECC key operations
from Crypto.Cipher import AES                     # AES for symmetric encryption (GCM)
from Crypto.Hash import SHA256                    # hashing for KDF
from Crypto.Protocol.KDF import HKDF              # HKDF to derive AES key from ECDH shared secret
from Crypto.Random import get_random_bytes        # secure random bytes
import binascii                                   # to print hex nicely

# 1) Generate recipient ECC key pair (curve P-256)
recipient_priv = ECC.generate(curve="P-256")      # recipient private key
recipient_pub = recipient_priv.public_key()       # recipient public key

# 2) Message to encrypt
message = "Secure Transactions"                    # plaintext
pt_bytes = message.encode('utf-8')                # convert to bytes

# 3) Sender: produce ephemeral key, derive shared secret, derive AES key, encrypt with AES-GCM
eph = ECC.generate(curve="P-256")                  # ephemeral private key for sender
# compute ECDH shared point: recipient_pub.pointQ * eph.d
shared_point = recipient_pub.pointQ * eph.d        # integer-coordinates point result
# derive symmetric key from shared_point.x via HKDF (use SHA-256)
shared_x = int(shared_point.x).to_bytes(32, 'big') # serialize x coordinate (32 bytes for P-256)
aes_key = HKDF(master=shared_x, key_len=32, salt=None, hashmod=SHA256)  # 32-byte AES key (AES-256)
# AES-GCM encrypt
nonce = get_random_bytes(12)                       # 12-byte nonce for GCM
cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # AES-GCM object
ciphertext, tag = cipher.encrypt_and_digest(pt_bytes)  # encrypt and get tag

# serialize ephemeral public point as x||y bytes for recipient
eph_x = int(eph.pointQ.x).to_bytes(32, 'big')      # x coordinate bytes
eph_y = int(eph.pointQ.y).to_bytes(32, 'big')      # y coordinate bytes
eph_pub_bytes = eph_x + eph_y                      # 64 bytes total

# show produced pieces in hex
print("Ephemeral public (hex):", binascii.hexlify(eph_pub_bytes).decode())
print("Nonce (hex):", nonce.hex())
print("GCM tag (hex):", tag.hex())
print("Ciphertext (hex):", ciphertext.hex())

# 4) Recipient: reconstruct ephemeral public, derive same shared secret and AES key, decrypt
# parse ephemeral public x and y
x_bytes = eph_pub_bytes[:32]                       # first 32 bytes
y_bytes = eph_pub_bytes[32:]                       # last 32 bytes
x_int = int.from_bytes(x_bytes, 'big')             # x as integer
y_int = int.from_bytes(y_bytes, 'big')             # y as integer
# construct ECC public key object for ephemeral public
eph_pub_key = ECC.construct(point_x=x_int, point_y=y_int, curve="P-256")
# derive shared point = eph_pub * recipient_priv.d
shared_point_rec = eph_pub_key.pointQ * recipient_priv.d
# derive AES key using same method
shared_x_rec = int(shared_point_rec.x).to_bytes(32, 'big')
aes_key_rec = HKDF(master=shared_x_rec, key_len=32, salt=None, hashmod=SHA256)
# decrypt using AES-GCM
dec_cipher = AES.new(aes_key_rec, AES.MODE_GCM, nonce=nonce)
plaintext_bytes = dec_cipher.decrypt_and_verify(ciphertext, tag)  # may raise if tag mismatch
plaintext = plaintext_bytes.decode('utf-8')       # decode to string

# print decrypted message
print("Decrypted message:", plaintext)
