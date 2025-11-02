# list of ciphertext (given in the problem)
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"  # given cipher text (uppercase)

# helper: compute gcd of two numbers (Euclidean algorithm)
def gcd(a, b):
    while b != 0:            # loop until remainder is zero
        a, b = b, a % b      # update a,b with remainder steps
    return a                 # return greatest common divisor

# helper: modular inverse of a mod m using extended Euclid
def modinv(a, m):
    # extended Euclidean algorithm to find inverse of a modulo m
    t0, t1 = 0, 1            # coefficients for inverse computation
    r0, r1 = m, a            # remainders
    while r1 != 0:           # loop until remainder becomes 0
        q = r0 // r1         # quotient
        r0, r1 = r1, r0 - q * r1   # update remainders
        t0, t1 = t1, t0 - q * t1   # update coefficients
    if r0 != 1:              # if gcd != 1, inverse doesn't exist
        return None
    return t0 % m            # ensure positive inverse modulo m

# convert letter (A-Z or a-z) to number 0-25
def char_to_num(ch):
    return ord(ch.upper()) - ord('A')   # map A->0, B->1, ..., Z->25

# convert number 0-25 back to uppercase letter
def num_to_char(n):
    return chr((n % 26) + ord('A'))     # map 0->A, 1->B, ..., wrap with %26

# list of candidate 'a' values that are coprime with 26 (only these have inverses)
valid_a = [a for a in range(1, 26) if gcd(a, 26) == 1]  # compute coprime a's

# normalize ciphertext to letters only (drop any non-letter, though not needed here)
ct = "".join([c for c in ciphertext if c.isalpha()]).upper()  # uppercase letters only

# known plaintext mapping: 'a' -> 'G', 'b' -> 'L'
known_plain_chars = ("A", "B")        # plaintext pair
known_cipher_chars = ("G", "L")       # corresponding cipher pair from problem

# convert known pairs to numeric values
p0 = char_to_num(known_plain_chars[0])  # numeric for 'A' -> 0
p1 = char_to_num(known_plain_chars[1])  # numeric for 'B' -> 1
c0 = char_to_num(known_cipher_chars[0]) # numeric for 'G'
c1 = char_to_num(known_cipher_chars[1]) # numeric for 'L'

# placeholder for discovered key(s)
found_keys = []                        # will store tuples (a,b) that satisfy known mapping

# brute-force over all valid 'a' and all possible 'b' (0..25)
for a in valid_a:                      # iterate possible multiplicative keys
    for b in range(26):                # iterate possible additive keys
        # compute encryption of p0 and p1 under candidate (a,b):
        # E(x) = (a*x + b) mod 26
        e0 = (a * p0 + b) % 26         # encryption result for first known plaintext char
        e1 = (a * p1 + b) % 26         # encryption result for second known plaintext char
        # if both match the known ciphertext numbers, record this key
        if e0 == c0 and e1 == c1:
            found_keys.append((a, b))  # save the discovered key

# if no keys found, report and stop
if not found_keys:
    print("No key found that maps 'ab' -> 'GL' via affine encryption.")
else:
    # try each found key (there should be at least one; typically exactly one)
    for (a, b) in found_keys:
        print(f"Found candidate key: a={a}, b={b}")  # show the discovered (a,b)

        # compute modular inverse of a for decryption: D(y) = a_inv * (y - b) mod 26
        a_inv = modinv(a, 26)          # modular inverse of a modulo 26
        if a_inv is None:              # if inverse doesn't exist, skip
            print("  but 'a' has no inverse mod 26 (shouldn't happen for valid_a).")
            continue

        # decrypt the entire ciphertext using the found key
        plaintext = ""                 # will collect decrypted letters
        for ch in ct:                  # iterate each ciphertext letter
            y = char_to_num(ch)        # convert ciphertext letter to number
            x = (a_inv * (y - b)) % 26 # apply affine decryption formula
            plaintext += num_to_char(x)  # convert number back to letter and append

        # print decrypted result (uppercase, spaces not restored)
        print("Decrypted plaintext (no spaces):", plaintext)
