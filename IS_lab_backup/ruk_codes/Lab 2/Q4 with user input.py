# import Triple DES (DES3) and padding helpers and hashing
from Crypto.Cipher import DES3                           # 3DES cipher
from Crypto.Util.Padding import pad, unpad               # PKCS#7 padding helpers
import hashlib                                           # for SHA-256 derivation
import sys                                               # for exiting on fatal error

# get plaintext message from user and convert to bytes
message = input("Enter the message to encrypt: ").encode('utf-8')   # encode to bytes

# get user key/passphrase (any length, we'll derive a safe 24-byte key)
user_key_str = input("Enter a key string (any length): ").strip()   # strip whitespace

# function: attempt to derive a non-degenerate 24-byte 3DES key from passphrase
def derive_non_degenerate_3des_key(passphrase, max_tries=1000):     # max_tries to avoid infinite loop
    # convert passphrase to bytes once
    base = passphrase.encode('utf-8')                               # base bytes of passphrase
    # try multiple salts (counter appended) until we find a valid key
    for i in range(max_tries):                                       # loop with small counter
        # create input for hash: passphrase (+ counter if i>0)
        data = base if i == 0 else base + b'|' + str(i).encode()     # different each iteration
        # produce 32-byte SHA-256 digest and take first 24 bytes for 3DES key
        candidate = hashlib.sha256(data).digest()[:24]               # 24-byte candidate key
        # adjust each byte parity as required by DES (one parity bit per byte)
        key_with_parity = DES3.adjust_key_parity(candidate)          # fix parity bits
        try:
            # try creating a DES3 cipher — PyCryptodome will raise ValueError if key degenerates
            DES3.new(key_with_parity, DES3.MODE_ECB)                 # test instantiation
            return key_with_parity                                   # success: return valid key
        except ValueError:
            # degeneracy or invalid key; continue loop and try next candidate
            continue
    # if loop finishes, we failed to find a non-degenerate key — raise error
    raise ValueError("Unable to derive a valid non-degenerate 3DES key from the input.")

# derive a safe 24-byte 3DES key from the user-supplied passphrase
try:
    key24 = derive_non_degenerate_3des_key(user_key_str)            # derive key (may raise)
except ValueError as e:
    print("Error:", e)                                              # print error message
    sys.exit(1)                                                     # exit program

# create 3DES cipher object in ECB mode using the derived key
cipher = DES3.new(key24, DES3.MODE_ECB)                             # cipher for encryption

# pad plaintext to DES block size (8 bytes) and encrypt the padded bytes
padded = pad(message, DES3.block_size)                               # PKCS#7 padding
ciphertext = cipher.encrypt(padded)                                  # encrypt padded plaintext

# print ciphertext in hex (IV not used in ECB)
print("\nCiphertext (hex):", ciphertext.hex())                       # show hex string

# decrypt: create a new cipher object with same key and decrypt the ciphertext
decipher = DES3.new(key24, DES3.MODE_ECB)                            # cipher for decryption
decrypted_padded = decipher.decrypt(ciphertext)                      # decrypt back to padded plaintext

# unpad decrypted bytes to recover original message and decode to string
try:
    decrypted = unpad(decrypted_padded, DES3.block_size).decode('utf-8')  # remove padding and decode
except ValueError:
    print("Decryption failed (padding error).")                       # error if padding invalid
    sys.exit(1)                                                       # exit on failure

# print recovered plaintext
print("Decrypted message:", decrypted)                                # show original message
