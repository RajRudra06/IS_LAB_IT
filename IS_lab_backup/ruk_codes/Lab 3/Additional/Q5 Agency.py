# Performance study: RSA-2048 vs EC-ElGamal (P-256) hybrid encryption
# - Hybrid RSA: AES-GCM for data + RSA-OAEP to protect AES key
# - EC-ElGamal: ephemeral ECDH (P-256) + HKDF -> AES-GCM
# - Measures keygen, encryption, decryption times and ciphertext sizes for various message sizes
# Requires: pip install pycryptodome

# import required primitives and helpers
from Crypto.PublicKey import RSA, ECC                       # RSA and ECC key objects
from Crypto.Cipher import PKCS1_OAEP, AES                   # RSA-OAEP and AES
from Crypto.Protocol.KDF import HKDF                        # HKDF for ECC-derived key
from Crypto.Hash import SHA256                              # SHA-256 for HKDF and OAEP
from Crypto.Random import get_random_bytes                  # secure random bytes
from Crypto.Util.Padding import pad, unpad                  # padding utilities (not needed for GCM)
import time                                                 # perf_counter for timing
import sys                                                  # exit on error

# helper: pretty bytes -> human readable
def human_readable(n):
    # convert bytes to KB/MB string
    for unit in ['B','KB','MB','GB']:
        if n < 1024.0:
            return f"{n:.2f} {unit}"
        n /= 1024.0
    return f"{n:.2f} TB"

# ---------------------------
# RSA hybrid helpers
# ---------------------------
def rsa_generate(bits=2048):
    # measure start time
    t0 = time.perf_counter()
    # generate RSA private key of 'bits' length
    priv = RSA.generate(bits)
    # measure elapsed ms
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    # return private key object, public key object, elapsed ms
    return priv, priv.publickey(), elapsed_ms

def rsa_hybrid_encrypt(data_bytes, rsa_pub):
    # generate a random AES-256 key
    aes_key = get_random_bytes(32)
    # AES-GCM uses a 12-byte nonce
    nonce = get_random_bytes(12)
    # create AES-GCM cipher and encrypt (time measured for symmetric part)
    t0 = time.perf_counter()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(data_bytes)
    sym_ms = (time.perf_counter() - t0) * 1000.0
    # encrypt AES key with RSA-OAEP (measure RSA key-encrypt time separately)
    rsa_cipher = PKCS1_OAEP.new(rsa_pub, hashAlgo=SHA256)
    t1 = time.perf_counter()
    enc_key = rsa_cipher.encrypt(aes_key)
    rsa_key_enc_ms = (time.perf_counter() - t1) * 1000.0
    # package everything into a dict
    package = {
        'enc_key': enc_key,    # RSA-encrypted AES key
        'nonce': nonce,        # AES-GCM nonce
        'tag': tag,            # AES-GCM tag
        'ciphertext': ciphertext
    }
    # return package and timing data
    return package, sym_ms, rsa_key_enc_ms

def rsa_hybrid_decrypt(package, rsa_priv):
    # unpack package
    enc_key = package['enc_key']
    nonce = package['nonce']
    tag = package['tag']
    ciphertext = package['ciphertext']
    # RSA-OAEP decrypt AES key (measure)
    rsa_cipher = PKCS1_OAEP.new(rsa_priv, hashAlgo=SHA256)
    t0 = time.perf_counter()
    aes_key = rsa_cipher.decrypt(enc_key)
    rsa_key_dec_ms = (time.perf_counter() - t0) * 1000.0
    # AES-GCM decrypt (measure)
    t1 = time.perf_counter()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)
    sym_dec_ms = (time.perf_counter() - t1) * 1000.0
    # return plaintext and timing details
    return plaintext, rsa_key_dec_ms, sym_dec_ms

# ---------------------------
# EC-ElGamal (ECIES-style) helpers using P-256
# ---------------------------
def ecc_generate(curve='P-256'):
    # measure start time
    t0 = time.perf_counter()
    # generate ECC private key
    priv = ECC.generate(curve=curve)
    # measure elapsed ms
    elapsed_ms = (time.perf_counter() - t0) * 1000.0
    # return private, public, elapsed time
    return priv, priv.public_key(), elapsed_ms

def ec_hybrid_encrypt(data_bytes, recipient_pub, curve='P-256'):
    # create ephemeral ECC key pair for sender
    eph = ECC.generate(curve=curve)
    # compute ECDH shared point = recipient_pub.pointQ * eph.d
    shared_point = recipient_pub.pointQ * eph.d
    # convert shared x to bytes (coord length at least 32 for P-256)
    shared_x_int = int(shared_point.x)
    coord_len = max((shared_x_int.bit_length() + 7) // 8, 32)
    shared_x_bytes = shared_x_int.to_bytes(coord_len, 'big')
    # derive AES-256 key from shared_x via HKDF-SHA256
    aes_key = HKDF(master=shared_x_bytes, key_len=32, salt=None, hashmod=SHA256)
    # AES-GCM encrypt with 12-byte nonce (measure symmetric time)
    nonce = get_random_bytes(12)
    t0 = time.perf_counter()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = aes.encrypt_and_digest(data_bytes)
    sym_ms = (time.perf_counter() - t0) * 1000.0
    # serialize ephemeral public point (x||y) with coord_len bytes each
    eph_x = int(eph.pointQ.x).to_bytes(coord_len, 'big')
    eph_y = int(eph.pointQ.y).to_bytes(coord_len, 'big')
    eph_pub_bytes = eph_x + eph_y
    # package ephemeral pub, nonce, tag, ciphertext
    package = {
        'eph_pub': eph_pub_bytes,
        'nonce': nonce,
        'tag': tag,
        'ciphertext': ciphertext
    }
    # return package and sym time
    return package, sym_ms

def ec_hybrid_decrypt(package, recipient_priv, curve='P-256'):
    # unpack package fields
    eph_pub_bytes = package['eph_pub']
    nonce = package['nonce']
    tag = package['tag']
    ciphertext = package['ciphertext']
    # compute coord length and split
    coord_len = len(eph_pub_bytes) // 2
    x_bytes = eph_pub_bytes[:coord_len]
    y_bytes = eph_pub_bytes[coord_len:]
    x_int = int.from_bytes(x_bytes, 'big')
    y_int = int.from_bytes(y_bytes, 'big')
    # reconstruct ephemeral public key object
    eph_pub = ECC.construct(point_x=x_int, point_y=y_int, curve=curve)
    # compute shared point = eph_pub.pointQ * recipient_priv.d
    shared_point = eph_pub.pointQ * recipient_priv.d
    shared_x_int = int(shared_point.x)
    shared_x_bytes = shared_x_int.to_bytes(coord_len, 'big')
    # derive AES-256 key via HKDF
    aes_key = HKDF(master=shared_x_bytes, key_len=32, salt=None, hashmod=SHA256)
    # AES-GCM decrypt and verify (measure)
    t0 = time.perf_counter()
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = aes.decrypt_and_verify(ciphertext, tag)
    sym_dec_ms = (time.perf_counter() - t0) * 1000.0
    # return plaintext and symmetric decryption time
    return plaintext, sym_dec_ms

# ---------------------------
# Experiment runner
# ---------------------------
def run_study(sizes_bytes):
    # container for results
    report = {'RSA': [], 'ECC': []}

    # generate RSA keys and measure time
    print("Generating RSA-2048 keypair...")
    rsa_priv, rsa_pub, rsa_keygen_ms = rsa_generate(2048)
    print(f" RSA keygen time: {rsa_keygen_ms:.3f} ms")

    # generate ECC keys and measure time
    print("Generating ECC-P256 keypair...")
    ecc_priv, ecc_pub, ecc_keygen_ms = ecc_generate('P-256')
    print(f" ECC keygen time: {ecc_keygen_ms:.3f} ms")

    # iterate sizes
    for size in sizes_bytes:
        print("\n" + "-"*60)
        print(f"Message size: {size} bytes ({human_readable(size)})")
        # create random data for this sample size
        data = get_random_bytes(size)

        # --- RSA hybrid experiment ---
        # encrypt
        t_start = time.perf_counter()
        rsa_package, rsa_sym_ms, rsa_key_enc_ms = rsa_hybrid_encrypt(data, rsa_pub)
        rsa_total_enc_ms = (time.perf_counter() - t_start) * 1000.0
        # compute package size: enc_key + nonce + tag + ciphertext
        rsa_pkg_size = len(rsa_package['enc_key']) + len(rsa_package['nonce']) + len(rsa_package['tag']) + len(rsa_package['ciphertext'])
        print(f" RSA: encrypt total {rsa_total_enc_ms:.3f} ms (sym {rsa_sym_ms:.3f} ms, rsa-key {rsa_key_enc_ms:.3f} ms); package {rsa_pkg_size} bytes")
        # decrypt and measure
        t_start = time.perf_counter()
        rsa_plain, rsa_key_dec_ms, rsa_sym_dec_ms = rsa_hybrid_decrypt(rsa_package, rsa_priv)
        rsa_total_dec_ms = (time.perf_counter() - t_start) * 1000.0
        print(f" RSA: decrypt total {rsa_total_dec_ms:.3f} ms (rsa-key-dec {rsa_key_dec_ms:.3f} ms, sym-dec {rsa_sym_dec_ms:.3f} ms)")
        # correctness
        ok_rsa = (rsa_plain == data)
        print(" RSA roundtrip OK:", ok_rsa)
        # record
        report['RSA'].append({
            'size': size,
            'enc_total_ms': rsa_total_enc_ms,
            'enc_sym_ms': rsa_sym_ms,
            'enc_key_ms': rsa_key_enc_ms,
            'dec_total_ms': rsa_total_dec_ms,
            'dec_key_ms': rsa_key_dec_ms,
            'dec_sym_ms': rsa_sym_dec_ms,
            'pkg_size': rsa_pkg_size,
            'ok': ok_rsa
        })

        # --- ECC hybrid experiment (EC-ElGamal / ECIES style) ---
        # encrypt
        t_start = time.perf_counter()
        ecc_package, ecc_sym_ms = ec_hybrid_encrypt(data, ecc_pub, curve='P-256')
        ecc_total_enc_ms = (time.perf_counter() - t_start) * 1000.0
        ecc_pkg_size = len(ecc_package['eph_pub']) + len(ecc_package['nonce']) + len(ecc_package['tag']) + len(ecc_package['ciphertext'])
        print(f" ECC: encrypt total {ecc_total_enc_ms:.3f} ms (sym {ecc_sym_ms:.3f} ms); package {ecc_pkg_size} bytes")
        # decrypt
        t_start = time.perf_counter()
        ecc_plain, ecc_sym_dec_ms = ec_hybrid_decrypt(ecc_package, ecc_priv, curve='P-256')
        ecc_total_dec_ms = (time.perf_counter() - t_start) * 1000.0
        print(f" ECC: decrypt total {ecc_total_dec_ms:.3f} ms (sym-dec {ecc_sym_dec_ms:.3f} ms)")
        ok_ecc = (ecc_plain == data)
        print(" ECC roundtrip OK:", ok_ecc)
        # record
        report['ECC'].append({
            'size': size,
            'enc_total_ms': ecc_total_enc_ms,
            'enc_sym_ms': ecc_sym_ms,
            'dec_total_ms': ecc_total_dec_ms,
            'dec_sym_ms': ecc_sym_dec_ms,
            'pkg_size': ecc_pkg_size,
            'ok': ok_ecc
        })

    # print summary table
    print("\n" + "="*80)
    print("Summary: RSA vs EC-ElGamal (hybrid) measurements")
    print(f"{'Alg':<6} {'Size':>10} {'Enc(ms)':>10} {'Dec(ms)':>10} {'Pkg(bytes)':>12} {'OK':>6}")
    for i, size in enumerate(sizes_bytes):
        r = report['RSA'][i]
        e = report['ECC'][i]
        print(f"{'RSA':<6} {r['size']:10d} {r['enc_total_ms']:10.3f} {r['dec_total_ms']:10.3f} {r['pkg_size']:12d} {str(r['ok']):>6}")
        print(f"{'ECC':<6} {e['size']:10d} {e['enc_total_ms']:10.3f} {e['dec_total_ms']:10.3f} {e['pkg_size']:12d} {str(e['ok']):>6}")
        print("-"*80)

    # final observations (simple)
    print("\nObservations (raw):")
    print(" - Key generation: RSA keygen tends to be slower and heavier than ECC keygen for similar security.")
    print(" - For large messages, symmetric AES-GCM (bulk) dominates time; public-key ops are small fixed overhead.")
    print(" - ECC hybrid usually has smaller metadata (ephemeral pub) vs RSA-encrypted AES key size.")
    return report

# ---------------------------
# main: choose message sizes and run
# ---------------------------
if __name__ == "__main__":
    # sizes to test: e.g., 1 KB, 10 KB, 100 KB
    sizes_kb = [1, 10, 100]                      # change or extend as needed
    sizes = [k*1024 for k in sizes_kb]           # convert KB -> bytes
    # run study
    results = run_study(sizes)
    # optionally, print nicer summary per algorithm
    print("\nDone. Results stored in 'results' dict variable.")
