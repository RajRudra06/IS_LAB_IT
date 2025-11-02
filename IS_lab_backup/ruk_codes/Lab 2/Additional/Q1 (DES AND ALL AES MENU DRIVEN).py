# ---------------------------
# Performance comparison: DES and AES (128/192/256) across modes (ECB, CBC, CFB, OFB)
# - Encrypts five preset messages using the SAME key for each algorithm
# - Measures encryption time using time.perf_counter (high-resolution)
# - Plots average encryption time (ms) for each algorithm-mode pair
# - Comments on every single line
# ---------------------------

# import cryptography primitives from pycryptodome
from Crypto.Cipher import DES, AES                        # DES and AES classes
from Crypto.Util.Padding import pad, unpad                # padding helpers
from Crypto.Random import get_random_bytes                # secure random bytes for IVs
import time                                               # for timing using perf_counter
import matplotlib.pyplot as plt                           # plotting library
import sys                                                # to exit on fatal error

# ---------------------------
# The five messages from your assignment (use these exact strings)
# ---------------------------
messages = [
    "Confidential Data",                                  # Q1
    "Sensitive Information",                              # Q2
    "Performance Testing of Encryption Algorithms",       # Q3
    "Classified Text",                                    # Q4
    "Top Secret Data"                                     # Q5
]

# ---------------------------
# Prompt user for a single base key string to use for all algorithms
# ---------------------------
base_key_input = input("Enter a base key string (any text; will be adapted to required lengths): ").strip()

# ---------------------------
# Helper: build or adapt key bytes to required length by repeating/truncating
# ---------------------------
def build_key_bytes(key_str, required_len):
    # convert provided key string to bytes (utf-8)
    b = key_str.encode('utf-8')
    # if exact length, return as-is
    if len(b) == required_len:
        return b
    # if shorter, repeat the bytes, then truncate to required length
    if len(b) < required_len:
        repeated = (b * ((required_len // len(b)) + 1))
        return repeated[:required_len]
    # if longer, simply truncate
    return b[:required_len]

# ---------------------------
# Helper: ensure DES key is acceptable (avoid some weak key rejections)
# Try small tweaks to last byte if pycryptodome rejects key instantiation
# ---------------------------
def make_valid_des_key(key_bytes):
    # create a mutable copy
    key = bytearray(key_bytes)
    # try up to 256 tweaks to the last byte to avoid weak-key rejection
    for i in range(256):
        try:
            # attempt to instantiate a DES cipher with the candidate key
            DES.new(bytes(key), DES.MODE_ECB)
            # success: return working key
            return bytes(key)
        except ValueError:
            # tweak final byte and retry
            key[-1] = (key[-1] + 1) & 0xFF
            continue
    # if we cannot find a valid key, raise error
    raise ValueError("Unable to derive a usable 8-byte DES key from the input.")

# ---------------------------
# Encrypt helpers for each algorithm/mode (return ciphertext bytes)
# We will use ECB/CBC/CFB/OFB modes. For CBC/CFB/OFB we need an IV of 8 bytes for DES and 16 for AES.
# For simplicity and reproducibility we generate a fresh random IV for each encryption and prepend IV to ciphertext.
# ---------------------------
def des_encrypt_with_mode(plaintext_str, key8, mode_name):
    # convert plaintext to bytes
    data = plaintext_str.encode('utf-8')
    # block size for DES is 8 bytes
    bs = DES.block_size
    # choose mode and build cipher object with an IV if needed
    if mode_name == "ECB":
        cipher = DES.new(key8, DES.MODE_ECB)               # ECB doesn't use IV
        padded = pad(data, bs)                             # pad to block size
        ct = cipher.encrypt(padded)                        # encrypt padded data
        return ct                                          # return ciphertext (no IV)
    else:
        iv = get_random_bytes(bs)                          # generate random IV (8 bytes)
        if mode_name == "CBC":
            cipher = DES.new(key8, DES.MODE_CBC, iv)      # CBC mode
            padded = pad(data, bs)                        # pad plaintext
            ct = cipher.encrypt(padded)                   # encrypt
            return iv + ct                                # prepend IV to ciphertext
        elif mode_name == "CFB":
            cipher = DES.new(key8, DES.MODE_CFB, iv)      # CFB mode
            # CFB works as stream; padding not strictly necessary, but keep consistent
            padded = pad(data, bs)
            ct = cipher.encrypt(padded)
            return iv + ct
        elif mode_name == "OFB":
            cipher = DES.new(key8, DES.MODE_OFB, iv)      # OFB mode
            padded = pad(data, bs)
            ct = cipher.encrypt(padded)
            return iv + ct
        else:
            raise ValueError("Unsupported DES mode")

def des_decrypt_with_mode(ciphertext_bytes, key8, mode_name):
    # block size for DES
    bs = DES.block_size
    # ECB: decrypt and unpad
    if mode_name == "ECB":
        cipher = DES.new(key8, DES.MODE_ECB)
        pt_padded = cipher.decrypt(ciphertext_bytes)
        return unpad(pt_padded, bs).decode('utf-8')
    else:
        # extract IV and ciphertext
        iv = ciphertext_bytes[:bs]
        ct = ciphertext_bytes[bs:]
        if mode_name == "CBC":
            cipher = DES.new(key8, DES.MODE_CBC, iv)
            pt_padded = cipher.decrypt(ct)
            return unpad(pt_padded, bs).decode('utf-8')
        elif mode_name == "CFB":
            cipher = DES.new(key8, DES.MODE_CFB, iv)
            pt_padded = cipher.decrypt(ct)
            return unpad(pt_padded, bs).decode('utf-8')
        elif mode_name == "OFB":
            cipher = DES.new(key8, DES.MODE_OFB, iv)
            pt_padded = cipher.decrypt(ct)
            return unpad(pt_padded, bs).decode('utf-8')
        else:
            raise ValueError("Unsupported DES mode")

def aes_encrypt_with_mode(plaintext_str, key_bytes, mode_name):
    # convert plaintext to bytes
    data = plaintext_str.encode('utf-8')
    # AES block size is 16 bytes
    bs = AES.block_size
    # ECB uses no IV
    if mode_name == "ECB":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        padded = pad(data, bs)
        ct = cipher.encrypt(padded)
        return ct
    else:
        # need 16-byte IV for AES
        iv = get_random_bytes(bs)
        if mode_name == "CBC":
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            padded = pad(data, bs)
            ct = cipher.encrypt(padded)
            return iv + ct
        elif mode_name == "CFB":
            cipher = AES.new(key_bytes, AES.MODE_CFB, iv)
            padded = pad(data, bs)
            ct = cipher.encrypt(padded)
            return iv + ct
        elif mode_name == "OFB":
            cipher = AES.new(key_bytes, AES.MODE_OFB, iv)
            padded = pad(data, bs)
            ct = cipher.encrypt(padded)
            return iv + ct
        else:
            raise ValueError("Unsupported AES mode")

def aes_decrypt_with_mode(ciphertext_bytes, key_bytes, mode_name):
    # AES block size
    bs = AES.block_size
    # ECB: decrypt and unpad
    if mode_name == "ECB":
        cipher = AES.new(key_bytes, AES.MODE_ECB)
        pt_padded = cipher.decrypt(ciphertext_bytes)
        return unpad(pt_padded, bs).decode('utf-8')
    else:
        # extract IV
        iv = ciphertext_bytes[:bs]
        ct = ciphertext_bytes[bs:]
        if mode_name == "CBC":
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
            pt_padded = cipher.decrypt(ct)
            return unpad(pt_padded, bs).decode('utf-8')
        elif mode_name == "CFB":
            cipher = AES.new(key_bytes, AES.MODE_CFB, iv)
            pt_padded = cipher.decrypt(ct)
            return unpad(pt_padded, bs).decode('utf-8')
        elif mode_name == "OFB":
            cipher = AES.new(key_bytes, AES.MODE_OFB, iv)
            pt_padded = cipher.decrypt(ct)
            return unpad(pt_padded, bs).decode('utf-8')
        else:
            raise ValueError("Unsupported AES mode")

# ---------------------------
# Modes to evaluate
# ---------------------------
modes = ["ECB", "CBC", "CFB", "OFB"]                       # list of modes to test

# ---------------------------
# Algorithms to evaluate and their required key sizes (in bytes)
# ---------------------------
algorithms = [
    ("DES", 8),                                           # DES uses 8-byte key
    ("AES-128", 16),                                      # AES-128 uses 16 bytes
    ("AES-192", 24),                                      # AES-192 uses 24 bytes
    ("AES-256", 32)                                       # AES-256 uses 32 bytes
]

# ---------------------------
# Prepare key bytes for each algorithm by adapting the single base key input
# ---------------------------
key_map = {}                                              # map algorithm name -> key bytes
for name, klen in algorithms:
    # adapt the base key to required length
    kb = build_key_bytes(base_key_input, klen)
    # if DES, check weak-key degeneracy and adjust
    if name == "DES":
        try:
            kb = make_valid_des_key(kb)
        except ValueError as e:
            print("Error preparing DES key:", e)
            sys.exit(1)
    key_map[name] = kb                                     # store key bytes

# ---------------------------
# Data structure to hold average encryption times (ms) per algorithm-mode
# We'll compute average across the five messages.
# ---------------------------
import math
results = {}                                               # dict {(alg,mode): avg_ms}

# ---------------------------
# Measure encryption time (single-run per message), average across messages
# ---------------------------
for (alg, klen) in algorithms:
    # for each mode
    for mode in modes:
        times = []                                         # list of times (ms) for each message
        # choose key bytes for this algorithm
        key_bytes = key_map[alg]
        # loop over messages and time encryption only (we exclude decryption time for the primary plot)
        for msg in messages:
            start = time.perf_counter()                    # high-resolution start time
            # call appropriate encrypt function depending on algorithm
            if alg == "DES":
                ct = des_encrypt_with_mode(msg, key_bytes, mode)   # encrypt
            else:
                ct = aes_encrypt_with_mode(msg, key_bytes, mode)  # AES variants
            elapsed_ms = (time.perf_counter() - start) * 1000     # elapsed time in milliseconds
            times.append(elapsed_ms)                      # record time for this message
            # quick verification (optional): decrypt and assert same plaintext (catch errors)
            try:
                if alg == "DES":
                    pt = des_decrypt_with_mode(ct, key_bytes, mode)
                else:
                    pt = aes_decrypt_with_mode(ct, key_bytes, mode)
                # If decryption failed or mismatch, report but continue
                if pt != msg:
                    print(f"Warning: roundtrip mismatch for {alg}-{mode} on message: '{msg}'")
            except Exception as e:
                print(f"Warning: decryption error for {alg}-{mode} on message '{msg}': {e}")
        # compute average time across the five messages
        avg = sum(times) / len(times) if len(times) > 0 else float('nan')
        results[(alg, mode)] = avg                         # store average ms

# ---------------------------
# Prepare data for plotting
# - x labels: "ALG-MODE" (e.g., "AES-128-CBC")
# - y values: average ms
# ---------------------------
labels = []                                                 # x-axis labels
values = []                                                 # y-axis values
for (alg, klen) in algorithms:
    for mode in modes:
        labels.append(f"{alg}-{mode}")                      # label string
        values.append(results[(alg, mode)])                 # average ms value

# ---------------------------
# Create a bar chart using matplotlib
# ---------------------------
plt.figure(figsize=(12, 6))                                 # create figure with size
x_positions = range(len(labels))                             # x positions for bars
# draw bars
plt.bar(x_positions, values, width=0.6)                      # simple bar chart
# label x-axis ticks
plt.xticks(x_positions, labels, rotation=45, ha='right')     # rotate labels for readability
# axis labels and title
plt.ylabel("Average encryption time (ms) across 5 messages")  # y-axis label
plt.title("Encryption time: DES & AES variants across modes (avg over 5 messages)")  # chart title
# draw horizontal grid lines for clarity
plt.grid(axis='y', linestyle='--', alpha=0.5)                # horizontal grid
plt.tight_layout()                                           # adjust layout to fit labels

# show plot to user
plt.show()                                                   # display chart window

# ---------------------------
# Print a small comparison table (text) and observations
# ---------------------------
print("\nAverage encryption times (ms) for each algorithm-mode (averaged over 5 messages):")
# header
print(f"{'Algorithm-Mode':30s} {'Avg (ms)':>10s}")
print("-" * 42)
# print each result row
for (alg, klen) in algorithms:
    for mode in modes:
        lab = f"{alg}-{mode}"
        val = results[(alg, mode)]
        print(f"{lab:30s} {val:10.6f}")

# ---------------------------
# Compare modes: compute average time across algorithms for each mode and print
# ---------------------------
print("\nAverage time by mode (averaged across algorithms):")
for mode in modes:
    # collect avg times for this mode across all algorithms
    times_mode = [results[(alg, mode)] for (alg, _) in algorithms]
    avg_mode = sum(times_mode) / len(times_mode)
    print(f"{mode:6s} : {avg_mode:.6f} ms (avg over {len(algorithms)} algorithms)")

# ---------------------------
# Final note printed for the
