import random
import math

# ----------------------------
# 1. Key Generation
# ----------------------------
def generate_keypair(bit_length=512):
    p = get_prime(bit_length // 2)
    q = get_prime(bit_length // 2)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e such that 1 < e < phi and gcd(e, phi) = 1
    e = 65537  # Common public exponent
    while math.gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    # Compute private exponent d
    d = pow(e, -1, phi)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

# Helper: generate random prime
def get_prime(bits):
    from Crypto.Util.number import getPrime
    return getPrime(bits)

# ----------------------------
# 2. Encryption
# ----------------------------
def encrypt(pub_key, m):
    e, n = pub_key
    c = pow(m, e, n)
    return c

# ----------------------------
# 3. Decryption
# ----------------------------
def decrypt(priv_key, c):
    d, n = priv_key
    m = pow(c, d, n)
    return m

# ----------------------------
# 4. Homomorphic Multiplication
# ----------------------------
def homomorphic_multiply(c1, c2, pub_key):
    _, n = pub_key
    return (c1 * c2) % n

# ----------------------------
# 5. Demonstration
# ----------------------------
# Generate keys
pub_key, priv_key = generate_keypair()

# Original numbers
a = 7
b = 3

# Encrypt both
cipher_a = encrypt(pub_key, a)
cipher_b = encrypt(pub_key, b)

# Perform homomorphic multiplication
cipher_product = homomorphic_multiply(cipher_a, cipher_b, pub_key)

# Decrypt the result
decrypted_product = decrypt(priv_key, cipher_product)

# Display results
print("Original numbers:", a, b)
print("Encrypted a:", cipher_a)
print("Encrypted b:", cipher_b)
print("Encrypted (a × b):", cipher_product)
print("Decrypted product:", decrypted_product)
