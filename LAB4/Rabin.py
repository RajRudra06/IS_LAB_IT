import random
from math import gcd

# ---------- Rabin Cryptosystem Core ----------

# Generate Rabin keypair (public key: n, private key: p, q)
def generate_keys(bits=512):
    def get_prime():
        while True:
            p = random.getrandbits(bits)
            if p % 4 == 3 and is_prime(p):
                return p

    def is_prime(n):
        if n < 2:
            return False
        for i in range(2, int(n ** 0.5) + 1):
            if n % i == 0:
                return False
        return True

    p = get_prime()
    q = get_prime()
    n = p * q
    return (n, p, q)

# Encrypt message (as integer)
def encrypt(message, n):
    m = int.from_bytes(message.encode(), 'big')
    c = pow(m, 2, n)
    return c

# Decrypt ciphertext (returns 4 possible plaintexts)
def decrypt(c, p, q):
    n = p * q

    # Compute square roots mod p and q
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)

    # Combine results using Chinese Remainder Theorem
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)

    r1 = (yp * p * mq + yq * q * mp) % n
    r2 = n - r1
    r3 = (yp * p * mq - yq * q * mp) % n
    r4 = n - r3

    return [r1, r2, r3, r4]

# ---------- Example Run ----------
n, p, q = generate_keys(256)   # smaller bit size for demo
message = "Patient Data"
cipher = encrypt(message, n)
possible_plaintexts = decrypt(cipher, p, q)

print("Ciphertext:", cipher)
print("\nPossible decrypted messages:")
for val in possible_plaintexts:
    try:
        print(val.to_bytes((val.bit_length() + 7) // 8, 'big').decode())
    except:
        pass  # skip non-decodable roots
