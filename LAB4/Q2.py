# """
# Demo Rabin KMS with Flask API, secure private-key storage (AES-GCM),
# key rotation/renewal, revocation, and audit logging.

# Install: pip install pycryptodome flask
# Run:    python rabin_kms.py
# """

# import os
# import json
# import time
# import threading
# import logging
# from functools import wraps
# from base64 import b64encode, b64decode
# from datetime import datetime, timedelta

# from flask import Flask, request, jsonify, abort

# # Crypto imports
# from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, inverse
# from Crypto.Random import get_random_bytes
# from Crypto.Cipher import AES
# from Crypto.Hash import SHA256

# # ---------------------------
# # Configuration (tweakable)
# # ---------------------------
# KEY_DIR = "kms_store"
# PUB_DIR = os.path.join(KEY_DIR, "public")
# PRIV_DIR = os.path.join(KEY_DIR, "private_enc")
# AUDIT_LOG = os.path.join(KEY_DIR, "audit.log")
# RSA_MASTER_PWD = "change_this_master_password"   # MUST be protected in prod (env/HSM)
# API_TOKEN = "demo-token"                         # simple API auth for demo (use OAuth/mTLS in prod)
# KEY_SIZE_BITS = 1024                              # default Rabin key size
# REDUNDANCY = b"\xAA\x55"                          # 2-byte redundancy to disambiguate roots
# RENEWAL_DAYS = 365                                # key renewal interval (demo uses days; can be seconds for testing)
# AUTO_RENEW = True

# # Create directories
# os.makedirs(PUB_DIR, exist_ok=True)
# os.makedirs(PRIV_DIR, exist_ok=True)
# os.makedirs(KEY_DIR, exist_ok=True)

# # ---------------------------
# # Logging / Audit
# # ---------------------------
# logger = logging.getLogger("rabin_kms")
# logger.setLevel(logging.INFO)
# fh = logging.FileHandler(AUDIT_LOG)
# fmt = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
# fh.setFormatter(fmt)
# logger.addHandler(fh)

# def audit(event, details=""):
#     msg = f"{event}: {details}"
#     logger.info(msg)

# # ---------------------------
# # Utility: derive master AES key from password
# # ---------------------------
# def derive_master_key(password: str) -> bytes:
#     # Simple KDF: SHA256(password || fixed_salt) -> 32 bytes key. Replace with scrypt/argon2 for prod.
#     salt = b"RabinKMS-SALT-v1"
#     h = SHA256.new()
#     h.update(password.encode('utf-8') + salt)
#     return h.digest()  # 32 bytes

# MASTER_KEY = derive_master_key(RSA_MASTER_PWD)

# # ---------------------------
# # AES-GCM helpers for private key storage
# # ---------------------------
# def encrypt_private_blob(blob: bytes, master_key: bytes) -> str:
#     nonce = get_random_bytes(12)
#     cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
#     ct, tag = cipher.encrypt_and_digest(blob)
#     packed = nonce + tag + ct
#     return b64encode(packed).decode('utf-8')

# def decrypt_private_blob(enc_b64: str, master_key: bytes) -> bytes:
#     data = b64decode(enc_b64)
#     nonce, tag, ct = data[:12], data[12:28], data[28:]
#     cipher = AES.new(master_key, AES.MODE_GCM, nonce=nonce)
#     return cipher.decrypt_and_verify(ct, tag)

# # ---------------------------
# # Rabin crypto functions
# # ---------------------------
# def gen_rabin_keypair(bits=KEY_SIZE_BITS):
#     # Need primes p,q where p % 4 == 3 and q % 4 == 3 for easy sqrt extraction
#     half = bits // 2
#     while True:
#         p = getPrime(half)
#         if p % 4 == 3:
#             break
#     while True:
#         q = getPrime(bits - half)
#         if q % 4 == 3 and q != p:
#             break
#     n = p * q
#     return {'p': p, 'q': q, 'n': n}

# def rabin_encrypt(message_bytes: bytes, n: int) -> int:
#     # Convert to integer with redundancy and square modulo n
#     m = REDUNDANCY + message_bytes
#     m_int = bytes_to_long(m)
#     if m_int >= n:
#         raise ValueError("Message too large for modulus; use hybrid chunking in production.")
#     c = pow(m_int, 2, n)
#     return c

# def _sqrt_mod_p(a, p):
#     # For p ≡ 3 (mod 4): sqrt(a) = a^{(p+1)/4} mod p (if exists)
#     return pow(a, (p + 1) // 4, p)

# def rabin_decrypt_all_roots(c: int, p: int, q: int):
#     # Compute square roots modulo p and q then CRT combine to up to 4 roots
#     r_p = _sqrt_mod_p(c % p, p)
#     r_q = _sqrt_mod_p(c % q, q)
#     # the two roots modulo p: ±r_p, modulo q: ±r_q
#     roots = []
#     # Precompute CRT coefficients
#     inv_p_mod_q = inverse(p, q)
#     inv_q_mod_p = inverse(q, p)
#     # combinations of signs
#     for sp in (r_p, (-r_p) % p):
#         for sq in (r_q, (-r_q) % q):
#             # Solve x ≡ sp (mod p), x ≡ sq (mod q)
#             # x = sp + p * ((sq - sp) * inv_p_mod_q mod q)
#             t = ((sq - sp) * inv_p_mod_q) % q
#             x = sp + p * t
#             x = x % (p * q)
#             roots.append(x)
#     # unique
#     roots = list({r for r in roots})
#     return roots

# def rabin_decrypt_select(c: int, p: int, q: int):
#     # Return the plaintext bytes by checking redundancy
#     roots = rabin_decrypt_all_roots(c, p, q)
#     for r in roots:
#         try:
#             b = long_to_bytes(r)
#             # ensure we have redundancy prefix
#             if len(b) >= len(REDUNDANCY) and b.startswith(REDUNDANCY):
#                 return b[len(REDUNDANCY):]
#         except Exception:
#             continue
#     raise ValueError("No valid plaintext found among roots (redundancy mismatch).")

# # ---------------------------
# # Key storage / metadata handling
# # ---------------------------
# def meta_path(entity_id):
#     return os.path.join(KEY_DIR, f"{entity_id}.json")

# def store_keypair(entity_id, keypair):
#     # store public key (n) plainly; private stored encrypted
#     ts = datetime.utcnow().isoformat()
#     pub = {'entity': entity_id, 'n': keypair['n'], 'generated': ts, 'expires': (datetime.utcnow() + timedelta(days=RENEWAL_DAYS)).isoformat(), 'revoked': False}
#     with open(os.path.join(PUB_DIR, f"{entity_id}.pub.json"), 'w') as f:
#         json.dump(pub, f)
#     # private blob as json
#     priv_blob = json.dumps({'p': keypair['p'], 'q': keypair['q'], 'n': keypair['n'], 'created': ts}).encode('utf-8')
#     enc = encrypt_private_blob(priv_blob, MASTER_KEY)
#     with open(os.path.join(PRIV_DIR, f"{entity_id}.priv.enc"), 'w') as f:
#         f.write(enc)
#     # metadata file
#     meta = {'entity': entity_id, 'public': os.path.join(PUB_DIR, f"{entity_id}.pub.json"), 'private': os.path.join(PRIV_DIR, f"{entity_id}.priv.enc")}
#     with open(meta_path(entity_id), 'w') as f:
#         json.dump(meta, f)
#     audit("KEY_GENERATED", f"{entity_id} n={keypair['n']}")

# def load_public(entity_id):
#     path = os.path.join(PUB_DIR, f"{entity_id}.pub.json")
#     if not os.path.exists(path):
#         return None
#     return json.load(open(path, 'r'))

# def load_private(entity_id):
#     path = os.path.join(PRIV_DIR, f"{entity_id}.priv.enc")
#     if not os.path.exists(path):
#         return None
#     enc = open(path, 'r').read()
#     blob = decrypt_private_blob(enc, MASTER_KEY)
#     return json.loads(blob.decode('utf-8'))

# def revoke_key(entity_id):
#     pub = load_public(entity_id)
#     if not pub:
#         return False
#     pub['revoked'] = True
#     pub['revoked_at'] = datetime.utcnow().isoformat()
#     with open(os.path.join(PUB_DIR, f"{entity_id}.pub.json"), 'w') as f:
#         json.dump(pub, f)
#     audit("KEY_REVOKED", entity_id)
#     return True

# def renew_key(entity_id, bits=KEY_SIZE_BITS):
#     newkp = gen_rabin_keypair(bits)
#     store_keypair(entity_id, newkp)
#     audit("KEY_RENEWED", entity_id)
#     return True

# # ---------------------------
# # Periodic renewal thread (demo)
# # ---------------------------
# def periodic_renewal(interval_days=RENEWAL_DAYS):
#     def worker():
#         while True:
#             audit("RENEWAL_PASS_START", "Starting scheduled renewal pass")
#             # load all public keys and renew those near expiry (for demo renew all)
#             for fname in os.listdir(PUB_DIR):
#                 if not fname.endswith(".pub.json"):
#                     continue
#                 entity_id = fname[:-9]
#                 # real logic: check expiry timestamp; here we renew all for demo
#                 try:
#                     renew_key(entity_id)
#                     audit("RENEWED_ENTITY", entity_id)
#                 except Exception as e:
#                     audit("RENEWAL_ERROR", f"{entity_id} error:{e}")
#             audit("RENEWAL_PASS_END", "Completed renewal pass")
#             time.sleep(interval_days * 24 * 3600)
#     t = threading.Thread(target=worker, daemon=True)
#     t.start()
#     return t

# # ---------------------------
# # Flask API (simple token auth)
# # ---------------------------
# app = Flask(__name__)

# def require_token(f):
#     @wraps(f)
#     def wrapper(*a, **kw):
#         token = request.headers.get("Authorization", "")
#         if token.startswith("Bearer "):
#             token = token[7:]
#         if token != API_TOKEN:
#             abort(401)
#         return f(*a, **kw)
#     return wrapper

# @app.route("/generate", methods=["POST"])
# @require_token
# def api_generate():
#     data = request.json or {}
#     entity = data.get("entity")
#     bits = int(data.get("bits", KEY_SIZE_BITS))
#     if not entity:
#         return jsonify({"error": "entity required"}), 400
#     kp = gen_rabin_keypair(bits)
#     store_keypair(entity, kp)
#     return jsonify({"entity": entity, "n": kp['n']}), 201

# @app.route("/public/<entity>", methods=["GET"])
# @require_token
# def api_get_public(entity):
#     pub = load_public(entity)
#     if not pub:
#         return jsonify({"error": "not found"}), 404
#     return jsonify(pub)

# @app.route("/private/<entity>", methods=["GET"])
# @require_token
# def api_get_private(entity):
#     # In real system private key distribution must be strongly authenticated and audited
#     priv = load_private(entity)
#     if not priv:
#         return jsonify({"error": "not found"}), 404
#     audit("PRIVATE_KEY_RETRIEVED", entity)
#     return jsonify(priv)

# @app.route("/revoke/<entity>", methods=["POST"])
# @require_token
# def api_revoke(entity):
#     ok = revoke_key(entity)
#     if not ok:
#         return jsonify({"error": "not found"}), 404
#     return jsonify({"revoked": entity})

# @app.route("/renew/<entity>", methods=["POST"])
# @require_token
# def api_renew(entity):
#     ok = renew_key(entity)
#     if not ok:
#         return jsonify({"error": "not found"}), 404
#     return jsonify({"renewed": entity})

# @app.route("/list", methods=["GET"])
# @require_token
# def api_list():
#     ents = []
#     for fname in os.listdir(PUB_DIR):
#         if fname.endswith(".pub.json"):
#             ents.append(fname[:-9])
#     return jsonify({"entities": ents})

# # ---------------------------
# # Simple example usage functions (local demo)
# # ---------------------------
# def demo_encrypt_decrypt(entity_id, plaintext: str):
#     """Demonstrate encryption using stored public key and decryption using stored private key."""
#     pub = load_public(entity_id)
#     priv = load_private(entity_id)
#     if not pub or not priv:
#         raise RuntimeError("keys missing")
#     n = pub['n']
#     p = priv['p']; q = priv['q']
#     mbytes = plaintext.encode('utf-8')
#     c = rabin_encrypt(mbytes, n)
#     audit("DEMO_ENCRYPT", f"{entity_id} c={c}")
#     # decrypt
#     recovered = rabin_decrypt_select(c, p, q)
#     audit("DEMO_DECRYPT", f"{entity_id} success")
#     return recovered.decode('utf-8')

# # ---------------------------
# # Startup: create sample entities and start renewal thread
# # ---------------------------
# if __name__ == "__main__":
#     # create a couple sample entities for demo if not exist
#     sample = ["HospitalA", "ClinicB"]
#     for s in sample:
#         if not os.path.exists(os.path.join(PUB_DIR, f"{s}.pub.json")):
#             kp = gen_rabin_keypair(KEY_SIZE_BITS)
#             store_keypair(s, kp)
#     audit("KMS_STARTED", f"Sample entities created: {sample}")
#     if AUTO_RENEW:
#         # for demo you might want to set a short interval by overriding RENEWAL_DAYS above
#         periodic_renewal(RENEWAL_DAYS)
#     # run Flask
#     print("Rabin KMS demo running. Use API token in Authorization header: 'Bearer demo-token'")
#     app.run(host="127.0.0.1", port=5000, debug=False)
















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
