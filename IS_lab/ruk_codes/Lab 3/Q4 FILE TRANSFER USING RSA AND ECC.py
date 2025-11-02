# Secure file-transfer comparison script (RSA-2048 vs ECC-P-256)
# - hybrid encryption: AES-GCM for file bytes + RSA-OAEP or ephemeral ECDH+HKDF for AES key protection
# - measures keygen, encryption and decryption times and ciphertext sizes
# - comments on every line

# import necessary modules from pycryptodome and Python stdlib
from Crypto.PublicKey import RSA, ECC                       # RSA and ECC key objects
from Crypto.Cipher import PKCS1_OAEP, AES                   # RSA-OAEP and AES primitives
from Crypto.Hash import SHA256                              # SHA-256 used by HKDF and OAEP
from Crypto.Protocol.KDF import HKDF                         # HKDF for ECC-derived AES key
from Crypto.Random import get_random_bytes                   # secure random bytes generator
from Crypto.Util.number import long_to_bytes, bytes_to_long  # helpers if needed
import time                                                  # high-resolution timing
import sys                                                   # for exit
import os                                                    # filesystem ops (if needed)

# helper to print human readable sizes
def human_readable_size(n):
    # convert bytes to KB/MB string
    for unit in ['B','KB','MB','GB']:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} TB"

# ---------------------------
# RSA key generation (2048-bit)
# ---------------------------
def rsa_generate_keypair(bits=2048):
    # record start time
    t0 = time.perf_counter()
    # generate RSA private key
    priv = RSA.generate(bits)
    # compute elapsed time in milliseconds
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    # get public key
    pub = priv.publickey()
    # return private key object, public key object, and elapsed ms
    return priv, pub, elapsed_ms

# ---------------------------
# ECC key generation (P-256)
# ---------------------------
def ecc_generate_keypair(curve='P-256'):
    # record start time
    t0 = time.perf_counter()
    # generate ECC private key
    priv = ECC.generate(curve=curve)
    # elapsed milliseconds
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    # get public key
    pub = priv.public_key()
    # return private, public, elapsed ms
    return priv, pub, elapsed_ms

# ---------------------------
# Hybrid RSA encryption: AES-GCM for data + RSA-OAEP to encrypt AES key
# ---------------------------
def hybrid_encrypt_rsa(file_bytes, rsa_pub):
    # generate random AES-256 key (32 bytes)
    aes_key = get_random_bytes(32)
    # create AES-GCM cipher with 12-byte nonce
    nonce = get_random_bytes(12)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    # time the symmetric encryption
    t0 = time.perf_counter()
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_bytes)
    sym_ms = (time.perf_counter() - t0) * 1000.0
    # RSA-OAEP encrypt the AES key with recipient public key
    rsa_cipher = PKCS1_OAEP.new(rsa_pub, hashAlgo=SHA256)
    t1 = time.perf_counter()
    enc_aes_key = rsa_cipher.encrypt(aes_key)
    rsa_enc_ms = (time.perf_counter() - t1) * 1000.0
    # package the encrypted components
    package = {
        'enc_aes_key': enc_aes_key,
        'nonce': nonce,
        'tag': tag,
        'ciphertext': ciphertext
    }
    # return package and timing numbers
    return package, sym_ms, rsa_enc_ms

# ---------------------------
# Hybrid RSA decryption
# ---------------------------
def hybrid_decrypt_rsa(package, rsa_priv):
    # unpack package
    enc_aes_key = package['enc_aes_key']
    nonce = package['nonce']
    tag = package['tag']
    ciphertext = package['ciphertext']
    # RSA-OAEP decrypt AES key using private key
    rsa_cipher = PKCS1_OAEP.new(rsa_priv, hashAlgo=SHA256)
    t0 = time.perf_counter()
    aes_key = rsa_cipher.decrypt(enc_aes_key)
    rsa_dec_ms = (time.perf_counter() - t0) * 1000.0
    # AES-GCM decrypt and verify tag
    t1 = time.perf_counter()
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    sym_dec_ms = (time.perf_counter() - t1) * 1000.0
    # return plaintext and timing details
    return plaintext, rsa_dec_ms, sym_dec_ms

# ---------------------------
# Hybrid ECC encryption: ephemeral ECDH + HKDF -> AES-GCM
# ---------------------------
def hybrid_encrypt_ecc(file_bytes, recipient_pub, curve='P-256'):
    # generate ephemeral ECC key (sender-side)
    eph = ECC.generate(curve=curve)
    # convert ephemeral public coordinates to Python ints
    eph_x = int(eph.pointQ.x)
    eph_y = int(eph.pointQ.y)
    # determine coordinate length from recipient public x (in bytes)
    rec_x = int(recipient_pub.pointQ.x)
    coord_len = (rec_x.bit_length() + 7) // 8
    # ensure a sensible minimum length (32 bytes for P-256)
    coord_len = max(coord_len, 32)
    # serialize ephemeral public point as x||y
    eph_pub_bytes = eph_x.to_bytes(coord_len, 'big') + eph_y.to_bytes(coord_len, 'big')
    # compute shared point = recipient_pub.pointQ * eph.d (ECDH)
    shared_point = recipient_pub.pointQ * eph.d
    # convert shared x coordinate to bytes
    shared_x = int(shared_point.x)
    shared_bytes = shared_x.to_bytes(coord_len, 'big')
    # derive AES-256 key via HKDF-SHA256 from shared_bytes
    aes_key = HKDF(master=shared_bytes, key_len=32, salt=None, hashmod=SHA256)
    # AES-GCM encryption
    nonce = get_random_bytes(12)
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    t0 = time.perf_counter()
    ciphertext, tag = aes_cipher.encrypt_and_digest(file_bytes)
    sym_ms = (time.perf_counter() - t0) * 1000.0
    # package ephemeral public, nonce, tag, ciphertext
    package = {
        'eph_pub': eph_pub_bytes,
        'nonce': nonce,
        'tag': tag,
        'ciphertext': ciphertext
    }
    # return package and symmetric encryption time
    return package, sym_ms

# ---------------------------
# Hybrid ECC decryption
# ---------------------------
def hybrid_decrypt_ecc(package, recipient_priv, curve='P-256'):
    # unpack package
    eph_pub = package['eph_pub']
    nonce = package['nonce']
    tag = package['tag']
    ciphertext = package['ciphertext']
    # split eph_pub into x and y bytes and convert to ints
    coord_len = len(eph_pub) // 2
    x_bytes = eph_pub[:coord_len]
    y_bytes = eph_pub[coord_len:]
    x_int = int.from_bytes(x_bytes, 'big')
    y_int = int.from_bytes(y_bytes, 'big')
    # reconstruct ephemeral public ECC key object
    eph_pub_obj = ECC.construct(point_x=x_int, point_y=y_int, curve=curve)
    # compute shared point = eph_pub.pointQ * recipient_priv.d
    shared_point = eph_pub_obj.pointQ * recipient_priv.d
    shared_x = int(shared_point.x)
    shared_bytes = shared_x.to_bytes(coord_len, 'big')
    # derive AES-256 key via HKDF-SHA256
    aes_key = HKDF(master=shared_bytes, key_len=32, salt=None, hashmod=SHA256)
    # AES-GCM decrypt and verify
    t0 = time.perf_counter()
    aes_cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes_cipher.decrypt_and_verify(ciphertext, tag)
    sym_dec_ms = (time.perf_counter() - t0) * 1000.0
    # return plaintext and time
    return plaintext, sym_dec_ms

# ---------------------------
# Helper: create random sample bytes of given size
# ---------------------------
def create_sample_bytes(size_bytes):
    # produce cryptographically-random bytes
    return get_random_bytes(size_bytes)

# ---------------------------
# Main experiment runner
# ---------------------------
def run_experiments(file_sizes_bytes):
    # results dictionary
    results = {'RSA': [], 'ECC': []}
    # generate RSA keypair and measure
    print("Generating RSA-2048 keypair...")
    rsa_priv, rsa_pub, rsa_keygen_ms = rsa_generate_keypair(2048)
    print(f" RSA keygen time: {rsa_keygen_ms:.3f} ms")
    # generate ECC keypair and measure
    print("Generating ECC-P256 keypair...")
    ecc_priv, ecc_pub, ecc_keygen_ms = ecc_generate_keypair('P-256')
    print(f" ECC keygen time: {ecc_keygen_ms:.3f} ms")
    # loop over sizes
    for size in file_sizes_bytes:
        print("\n" + "-"*60)
        print(f"Testing file size: {size} bytes ({human_readable_size(size)})")
        # create sample bytes
        file_bytes = create_sample_bytes(size)
        # ----- RSA hybrid -----
        # encrypt
        t_enc_start = time.perf_counter()
        rsa_package, rsa_sym_ms, rsa_key_enc_ms = hybrid_encrypt_rsa(file_bytes, rsa_pub)
        total_rsa_enc_ms = (time.perf_counter() - t_enc_start) * 1000.0
        rsa_ct_size = len(rsa_package['ciphertext']) + len(rsa_package['enc_aes_key']) + len(rsa_package['nonce']) + len(rsa_package['tag'])
        print(f" RSA: encrypt done. Total encrypt time: {total_rsa_enc_ms:.3f} ms (sym: {rsa_sym_ms:.3f} ms, rsa-key: {rsa_key_enc_ms:.3f} ms). Ciphertext size: {rsa_ct_size} bytes")
        # decrypt
        t_dec_start = time.perf_counter()
        rsa_plain, rsa_key_dec_ms, rsa_sym_dec_ms = hybrid_decrypt_rsa(rsa_package, rsa_priv)
        total_rsa_dec_ms = (time.perf_counter() - t_dec_start) * 1000.0
        print(f" RSA: decrypt done. Total decrypt time: {total_rsa_dec_ms:.3f} ms (rsa-key-dec: {rsa_key_dec_ms:.3f} ms, sym-dec: {rsa_sym_dec_ms:.3f} ms)")
        ok_rsa = rsa_plain == file_bytes
        print(" RSA: correct roundtrip:", ok_rsa)
        # store
        results['RSA'].append({
            'size': size,
            'enc_total_ms': total_rsa_enc_ms,
            'enc_sym_ms': rsa_sym_ms,
            'enc_key_ms': rsa_key_enc_ms,
            'dec_total_ms': total_rsa_dec_ms,
            'dec_key_ms': rsa_key_dec_ms,
            'dec_sym_ms': rsa_sym_dec_ms,
            'ciphertext_size': rsa_ct_size,
            'ok': ok_rsa
        })
        # ----- ECC hybrid -----
        t_enc_start = time.perf_counter()
        ecc_package, ecc_sym_ms = hybrid_encrypt_ecc(file_bytes, ecc_pub, curve='P-256')
        total_ecc_enc_ms = (time.perf_counter() - t_enc_start) * 1000.0
        ecc_ct_size = len(ecc_package['ciphertext']) + len(ecc_package['eph_pub']) + len(ecc_package['nonce']) + len(ecc_package['tag'])
        print(f" ECC: encrypt done. Total encrypt time: {total_ecc_enc_ms:.3f} ms (sym: {ecc_sym_ms:.3f} ms). Ciphertext size: {ecc_ct_size} bytes")
        # decrypt
        t_dec_start = time.perf_counter()
        ecc_plain, ecc_sym_dec_ms = hybrid_decrypt_ecc(ecc_package, ecc_priv, curve='P-256')
        total_ecc_dec_ms = (time.perf_counter() - t_dec_start) * 1000.0
        print(f" ECC: decrypt done. Total decrypt time: {total_ecc_dec_ms:.3f} ms (sym-dec: {ecc_sym_dec_ms:.3f} ms)")
        ok_ecc = ecc_plain == file_bytes
        print(" ECC: correct roundtrip:", ok_ecc)
        # store
        results['ECC'].append({
            'size': size,
            'enc_total_ms': total_ecc_enc_ms,
            'enc_sym_ms': ecc_sym_ms,
            'dec_total_ms': total_ecc_dec_ms,
            'dec_sym_ms': ecc_sym_dec_ms,
            'ciphertext_size': ecc_ct_size,
            'ok': ok_ecc
        })
    # print summary
    print("\n" + "="*80)
    print("Summary (times in ms, sizes in bytes):")
    print("- RSA results -")
    for row in results['RSA']:
        print(f"size={row['size']} | enc_total={row['enc_total_ms']:.3f} | enc_sym={row['enc_sym_ms']:.3f} | enc_key={row['enc_key_ms']:.3f} | dec_total={row['dec_total_ms']:.3f} | dec_key={row['dec_key_ms']:.3f} | dec_sym={row['dec_sym_ms']:.3f} | csize={row['ciphertext_size']} | ok={row['ok']}")
    print("- ECC results -")
    for row in results['ECC']:
        print(f"size={row['size']} | enc_total={row['enc_total_ms']:.3f} | enc_sym={row['enc_sym_ms']:.3f} | dec_total={row['dec_total_ms']:.3f} | dec_sym={row['dec_sym_ms']:.3f} | csize={row['ciphertext_size']} | ok={row['ok']}")
    # brief observations
    print("\nObservations:")
    print(" - RSA key generation time printed above; ECC key generation time printed above.")
    print(" - For large files, AES-GCM (symmetric) dominates total time; public-key ops are fixed-size overhead.")
    print(" - ECC hybrid typically has smaller metadata overhead than RSA-OAEP encrypted AES key.")
    print("Done.")
    return results

# ---------------------------
# Script entrypoint
# ---------------------------
if __name__ == "__main__":
    # choose default sizes: 1KB, 1MB, 10MB
    choice = input("Run default sizes [1KB, 1MB, 10MB]? (y/n) ").strip().lower()
    if choice in ('', 'y', 'yes'):
        sizes = [1024, 1024*1024, 10*1024*1024]
    else:
        s = input("Enter sizes in KB, comma-separated (e.g. '1,1024,10240'): ").strip()
        try:
            parts = [int(x.strip()) for x in s.split(',') if x.strip()]
            sizes = [p*1024 for p in parts]
        except Exception:
            print("Invalid input; exiting.")
            sys.exit(1)
    # run experiments
    run_experiments(sizes)
