# ElGamal encryption/decryption (single-block, ensures p > message integer)
# Requires: pip install pycryptodome

# import necessary helpers
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes  # big-number helpers
from Crypto.Random import random                                        # CSPRNG helper
import secrets                                                           # secure random
import math                                                              # for math ops

# ---------------------------
# Message to encrypt
# ---------------------------
message = "Confidential Data"                    # plaintext string to encrypt
message_bytes = message.encode('utf-8')          # convert plaintext to bytes
m_int = bytes_to_long(message_bytes)             # convert bytes -> integer for ElGamal
# show integer size info (for debugging / understanding)
print("Message as integer (decimal):", m_int)
print("Message bit-length:", m_int.bit_length())

# ---------------------------
# Choose prime p large enough so p > m_int
# We'll pick a prime with bit-length = message_bits + 64 (safety margin)
# ---------------------------
msg_bits = max(8, m_int.bit_length())            # at least 8 bits
p_bits = msg_bits + 64                           # add 64-bit safety margin
# ensure p_bits is at least 128 for reasonable demo security
if p_bits < 128:
    p_bits = 128
# generate a prime p of p_bits length
p = getPrime(p_bits)                             # generate a random prime p (probable prime)
# choose generator g; for demo we use small generator 2 (works for many p)
g = 2

# ---------------------------
# Private/public key generation
# Private key x random in [1, p-2]
# Public key h = g^x mod p
# ---------------------------
x = secrets.randbelow(p-2) + 1                   # private key (secure random)
h = pow(g, x, p)                                 # public component

# show public key components for reference
print("\nPublic key (p, g, h):")
print(" p (hex) :", hex(p))
print(" g       :", g)
print(" h (hex) :", hex(h))
print("Private key x (hex):", hex(x))

# ---------------------------
# Encryption
# Pick ephemeral y in [1, p-2], compute c1 = g^y mod p, s = h^y mod p, c2 = (m * s) mod p
# ---------------------------
y = secrets.randbelow(p-2) + 1                   # ephemeral random
c1 = pow(g, y, p)                                # c1 = g^y mod p
s = pow(h, y, p)                                 # shared secret = h^y mod p
c2 = (m_int * s) % p                             # c2 = m * s (mod p)

# show ciphertext components
print("\nCiphertext components:")
print(" c1 (hex):", hex(c1))
print(" c2 (hex):", hex(c2))

# ---------------------------
# Decryption
# Compute shared secret s' = c1^x mod p, invert it, recover m = c2 * s_inv mod p
# ---------------------------
s_dec = pow(c1, x, p)                            # s' = c1^x mod p
# compute modular inverse of s_dec mod p using pow (p is prime => s_dec^(p-2) mod p)
s_inv = pow(s_dec, p-2, p)                       # modular inverse of s_dec modulo p
m_recovered_int = (c2 * s_inv) % p               # recovered integer message

# convert integer back to bytes and then to string
m_recovered_bytes = long_to_bytes(m_recovered_int)  # convert long -> bytes
try:
    m_recovered = m_recovered_bytes.decode('utf-8')  # decode bytes -> string
except Exception:
    # if decode fails, we still print raw bytes
    m_recovered = None

# ---------------------------
# Results
# ---------------------------
print("\nRecovered integer:", m_recovered_int)
print("Recovered bytes (hex):", m_recovered_bytes.hex())
if m_recovered is not None:
    print("Recovered message:", m_recovered)
else:
    print("Recovered bytes could not be decoded as UTF-8; raw bytes shown above.")
