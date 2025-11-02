# Fixed ElGamal (per-byte) encryption/decryption
import secrets

# Given parameters
p = 7919
g = 2
h_given = 6465
x = 2999

# Recompute h to ensure consistency with private key
h_correct = pow(g, x, p)
if h_correct != h_given:
    print(f"⚠ Warning: provided h={h_given} does not match g^x mod p={h_correct}")
    h = h_correct
else:
    h = h_given

# Plaintext
plaintext = "Asymmetric Algorithms"
pt_bytes = plaintext.encode()

# --- Encryption ---
cipher_pairs = []
for m in pt_bytes:
    y = secrets.randbelow(p - 2) + 1
    c1 = pow(g, y, p)
    s = pow(h, y, p)
    c2 = (m * s) % p
    cipher_pairs.append((c1, c2))

print("Ciphertext pairs (first 5):", cipher_pairs[:5])

# --- Decryption ---
decrypted = bytearray()
for (c1, c2) in cipher_pairs:
    s_dec = pow(c1, x, p)
    s_inv = pow(s_dec, p - 2, p)   # modular inverse
    m = (c2 * s_inv) % p
    decrypted.append(m)            # now always in 0–255

# Convert back to string
recovered_text = decrypted.decode()
print("Recovered text:", recovered_text)
