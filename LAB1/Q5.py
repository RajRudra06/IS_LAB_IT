# deduce Caesar shift from a known ciphertext->plaintext pair and decrypt a target
def deduce_shift(ct, pt):
    # use first character of each (case-insensitive)
    return (ord(ct[0].upper()) - ord(pt[0].upper())) % 26

def caesar_decrypt(ciphertext, shift):
    out = []
    for ch in ciphertext:
        if ch.isalpha():
            # work in uppercase for output
            x = (ord(ch.upper()) - ord('A') - shift) % 26
            out.append(chr(ord('A') + x))
        else:
            out.append(ch)
    return ''.join(out)

known_ct = "CIW"
known_pt = "yes"
target_ct = "XVIEWYWI"

shift = deduce_shift(known_ct, known_pt)
plaintext = caesar_decrypt(target_ct, shift)

print("Shift (encryption) =", shift)
print("Decrypted plaintext  =", plaintext)
