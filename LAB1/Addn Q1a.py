# Eve intercepts: plaintext "abcdefghi" → ciphertext "CABDEHFGL"
# Task:
# a) Identify type of attack
# b) Find size of permutation key

# Eve is performing a known-plaintext attack because she knows both plaintext and ciphertext.

# === Part (a): Type of attack ===
attack_type = "Known-plaintext attack"
print("a) Type of attack:", attack_type)

# === Part (b): Derive permutation and its size ===
def derive_permutation(pt, ct):
    pt = pt.upper()
    ct = ct.upper()
    if len(pt) != len(ct):
        raise ValueError("Plaintext and ciphertext must have same length")
    perm = []
    for i, ch in enumerate(pt):
        j = ct.find(ch)
        if j == -1:
            raise ValueError(f"Character {ch} from plaintext not found in ciphertext")
        perm.append(j + 1)  # 1-based position
    return perm

# given data
plaintext = "abcdefghi"
ciphertext = "CABDEHFGL"

perm = derive_permutation(plaintext, ciphertext)
print("b) Permutation (1-based):", perm)
print("   Size of permutation key:", len(perm))
