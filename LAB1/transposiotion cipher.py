import math

def encrypt_transposition(plaintext, key):
    """Encrypt plaintext using a numeric key (permutation of columns)."""
    plaintext = plaintext.replace(" ","").upper()
    n = len(key)
    # pad plaintext to full blocks
    pad_len = (-len(plaintext)) % n
    plaintext += 'X' * pad_len
    ciphertext = ""
    for i in range(n):
        col = key.index(i+1)  # column in plaintext block
        for j in range(i, len(plaintext), n):
            ciphertext += plaintext[j]
    return ciphertext

def decrypt_transposition(ciphertext, key):
    n = len(key)
    num_rows = len(ciphertext)//n
    pt_matrix = ['']*num_rows
    idx = 0
    for k in range(n):
        col = key.index(k+1)
        for r in range(num_rows):
            pt_matrix[r] += ciphertext[idx]
            idx += 1
    return ''.join(pt_matrix)

# Example usage
plaintext = "HELLO WORLD"
key = [3,1,4,2]  # numeric key indicating column order

ct = encrypt_transposition(plaintext, key)
print("Ciphertext:", ct)

pt = decrypt_transposition(ct, key)
print("Decrypted:", pt)
