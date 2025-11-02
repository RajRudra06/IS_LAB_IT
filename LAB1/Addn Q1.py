# derive permutation from known plaintext/ciphertext pair
def derive_permutation(pt, ct):
    pt = pt.upper()
    ct = ct.upper()
    n = len(pt)
    if len(ct) != n:
        raise ValueError("known plaintext and ciphertext must be same length")
    perm = []
    for i, ch in enumerate(pt):
        j = ct.find(ch)
        if j == -1:
            raise ValueError(f"char {ch} from plaintext not found in ciphertext")
        perm.append(j+1)  # 1-based positions
    return perm  # perm[i] = ciphertext position (1-based) of plaintext char at index i

# decrypt a ciphertext that was encrypted with the keyed transposition
def transposition_decrypt(ctext, perm):
    n = len(perm)
    ct = ''.join(ctext.split())  # remove spaces if any
    # pad with X to full blocks
    pad_len = (-len(ct)) % n
    ct_padded = ct + ('X' * pad_len)
    plaintext_chars = []
    for b in range(0, len(ct_padded), n):
        block = ct_padded[b:b+n]
        # plaintext char at i was moved to ciphertext position perm[i]-1
        # so plaintext[i] = block[ perm[i]-1 ]
        pt_block = []
        for i in range(n):
            src_idx = perm[i]-1
            pt_block.append(block[src_idx])
        plaintext_chars.append(''.join(pt_block))
    pt = ''.join(plaintext_chars)
    if pad_len:
        pt = pt[:-pad_len]
    return pt

# example usage
known_pt = "abcdefghi"
known_ct = "CABDEHFGL"

perm = derive_permutation(known_pt, known_ct)
print("Permutation (1-based, plaintext-index -> ciphertext-position):", perm)
# permutation size
print("Permutation size:", len(perm))

# ciphertext to decrypt (example from earlier)
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"
# keep non-letters as-is or remove them before decryption. Here we remove non-letters to apply the block transposition.
import re
clean_ct = re.sub(r'[^A-Z]', '', ciphertext.upper())

decrypted = transposition_decrypt(clean_ct, perm)
print("\nDecrypted (non-letters removed):")
print(decrypted)

# If you want to preserve separators (like / &), split by non-letters and decrypt each alpha segment separately:
segments = re.split(r'([^A-Z]+)', ciphertext.upper())  # keeps separators
out = []
for seg in segments:
    if seg and seg.isalpha():
        out.append(transposition_decrypt(seg, perm))
    else:
        out.append(seg)
print("\nDecrypted with separators preserved:")
print(''.join(out))
