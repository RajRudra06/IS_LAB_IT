from Crypto.PublicKey import ElGamal
from Crypto.Random import get_random_bytes, random
from Crypto.Util.number import bytes_to_long, long_to_bytes

# -------------------
# Step 1: Generate ElGamal keypair (or use given p, g, h)
# -------------------
key = ElGamal.generate(2048, random.get_random_bytes)
public_key = key.publickey()  # (p, g, h)
private_key = key              # x

# -------------------
# Step 2: Prepare message as integer
# -------------------
message = b"Confidential Data"
m_int = bytes_to_long(message)  # convert bytes to integer

# -------------------
# Step 3: Encrypt message
# -------------------
k = random.StrongRandom().randint(1, key.p-2)  # ephemeral key k
ciphertext = public_key.encrypt(m_int, k)      # returns tuple (c1, c2)
print("Ciphertext:", ciphertext)

# -------------------
# Step 4: Decrypt message
# -------------------
m_decrypted = private_key.decrypt(ciphertext)
plaintext = long_to_bytes(m_decrypted)
print("Decrypted message:", plaintext.decode('utf-8'))



# with given values already 

from Crypto.Util.number import bytes_to_long, long_to_bytes
import random

# -------------------
# Step 1: Given ElGamal keys
# -------------------
p = 7919
g = 2
h = 6465
x = 2999   # private key

# -------------------
# Step 2: Convert message to integer
# -------------------
message = b"Asymmetric Algorithms"
m = bytes_to_long(message)   # convert bytes -> integer
print("Message as integer:", m)

# -------------------
# Step 3: Encrypt message
# -------------------
# Choose ephemeral key k (1 <= k <= p-2, coprime to p-1)
k = random.randint(1, p-2)
while True:
    if pow(g, k, p) != 0:
        break
    k = random.randint(1, p-2)

c1 = pow(g, k, p)
c2 = (m * pow(h, k, p)) % p

ciphertext = (c1, c2)
print("Ciphertext:", ciphertext)

# -------------------
# Step 4: Decrypt message
# -------------------
# m = c2 * (c1^x)^(-1) mod p
s = pow(c1, x, p)                  # shared secret
s_inv = pow(s, -1, p)              # modular inverse
m_decrypted = (c2 * s_inv) % p     # recover integer
plaintext = long_to_bytes(m_decrypted)
print("Decrypted message:", plaintext.decode('utf-8'))
