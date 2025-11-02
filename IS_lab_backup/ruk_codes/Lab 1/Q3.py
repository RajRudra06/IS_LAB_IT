# ---------------------------
# Playfair Cipher - Full Code with Encryption + Decryption
# ---------------------------

# Step 1: Generate 5x5 Key Matrix
def generate_matrix(key):
    key = key.lower().replace("j", "i")  # convert to lowercase and replace 'j' with 'i'
    matrix = ""  # string to collect matrix letters

    # Insert key letters first (avoid duplicates)
    for char in key:
        if char not in matrix and char.isalpha():
            matrix += char

    # Fill remaining letters of alphabet
    for char in "abcdefghijklmnopqrstuvwxyz":
        if char == "j":  # skip j
            continue
        if char not in matrix:
            matrix += char

    # Return matrix as 5x5 grid
    return [list(matrix[i * 5:(i + 1) * 5]) for i in range(5)]


# Step 2: Preprocess plaintext into digraphs
def preprocess(text):
    text = text.lower().replace(" ", "").replace("j", "i")  # normalize text
    pairs = []  # list of pairs
    i = 0
    while i < len(text):
        a = text[i]
        if i + 1 < len(text):
            b = text[i + 1]
            if a == b:  # same letter → insert 'x'
                pairs.append(a + "x")
                i += 1
            else:  # normal pair
                pairs.append(a + b)
                i += 2
        else:  # last letter alone → add 'x'
            pairs.append(a + "x")
            i += 1
    return pairs


# Step 3: Find position of a character in the matrix
def pos(matrix, char):
    for r in range(5):
        for c in range(5):
            if matrix[r][c] == char:
                return r, c
    return None


# Step 4: Encrypt using Playfair rules
def encrypt(message, key):
    matrix = generate_matrix(key)  # build key matrix
    pairs = preprocess(message)  # break into pairs
    cipher = ""  # encrypted result

    for a, b in pairs:
        r1, c1 = pos(matrix, a)
        r2, c2 = pos(matrix, b)

        if r1 == r2:  # same row → take next right
            cipher += matrix[r1][(c1 + 1) % 5]
            cipher += matrix[r2][(c2 + 1) % 5]
        elif c1 == c2:  # same column → take below
            cipher += matrix[(r1 + 1) % 5][c1]
            cipher += matrix[(r2 + 1) % 5][c2]
        else:  # rectangle swap
            cipher += matrix[r1][c2]
            cipher += matrix[r2][c1]
    return cipher


# Step 5: Decrypt using Playfair rules
def decrypt(cipher, key):
    matrix = generate_matrix(key)  # build key matrix
    plaintext = ""  # decrypted result

    # process cipher in pairs (2 letters at a time)
    for i in range(0, len(cipher), 2):
        a, b = cipher[i], cipher[i + 1]
        r1, c1 = pos(matrix, a)
        r2, c2 = pos(matrix, b)

        if r1 == r2:  # same row → take previous left
            plaintext += matrix[r1][(c1 - 1) % 5]
            plaintext += matrix[r2][(c2 - 1) % 5]
        elif c1 == c2:  # same column → take above
            plaintext += matrix[(r1 - 1) % 5][c1]
            plaintext += matrix[(r2 - 1) % 5][c2]
        else:  # rectangle swap
            plaintext += matrix[r1][c2]
            plaintext += matrix[r2][c1]
    return plaintext


# ----------------- Test -----------------
message = "The key is hidden under the door pad"  # given message
key = "GUIDANCE"  # given key

# Generate and print key matrix
matrix = generate_matrix(key)
print("Key Matrix:")
for row in matrix:
    print(row)

# Preprocess plaintext into digraphs
pairs = preprocess(message)
print("\nPlaintext Pairs:", pairs)

# Encrypt
ciphertext = encrypt(message, key)
print("\nEncrypted Text:", ciphertext)

# Decrypt
decrypted = decrypt(ciphertext, key)
print("Decrypted Text:", decrypted)
