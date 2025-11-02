import random
import math

# ----------------------------
# 1. Key Generation
# ----------------------------
def generate_keypair(bit_length=512):
    # Generate two large primes p and q
    p = get_prime(bit_length // 2)
    q = get_prime(bit_length // 2)
    n = p * q
    λ = math.lcm(p - 1, q - 1)  # Carmichael’s function
    g = n + 1  # Common choice for g
    μ = pow(L(pow(g, λ, n * n), n) , -1, n)
    public_key = (n, g)
    private_key = (λ, μ)
    return public_key, private_key

# Helper function for key generation
def get_prime(bits):
    from Crypto.Util.number import getPrime
    return getPrime(bits)

def L(u, n):
    return (u - 1) // n

# ----------------------------
# 2. Encryption
# ----------------------------
def encrypt(pub_key, m):
    n, g = pub_key
    r = random.randrange(1, n)
    while math.gcd(r, n) != 1:
        r = random.randrange(1, n)
    c = (pow(g, m, n * n) * pow(r, n, n * n)) % (n * n)
    return c

# ----------------------------
# 3. Decryption
# ----------------------------
def decrypt(priv_key, pub_key, c):
    λ, μ = priv_key
    n, g = pub_key
    u = pow(c, λ, n * n)
    L_of_u = L(u, n)
    m = (L_of_u * μ) % n
    return m

# ----------------------------
# 4. Homomorphic Addition
# ----------------------------
def homomorphic_add(c1, c2, pub_key):
    n, _ = pub_key
    return (c1 * c2) % (n * n)

# ----------------------------
# 5. Demonstration
# ----------------------------
# Generate keys
pub_key, priv_key = generate_keypair()

# Original messages
a = 15
b = 25

# Encrypt both integers
cipher_a = encrypt(pub_key, a)
cipher_b = encrypt(pub_key, b)

# Perform homomorphic addition
cipher_sum = homomorphic_add(cipher_a, cipher_b, pub_key)

# Decrypt the result
decrypted_sum = decrypt(priv_key, pub_key, cipher_sum)

# Display results
print("Original numbers:", a, b)
print("Encrypted a:", cipher_a)
print("Encrypted b:", cipher_b)
print("Encrypted (a + b):", cipher_sum)
print("Decrypted sum:", decrypted_sum)
