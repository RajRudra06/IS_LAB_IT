# -----------------------------
# Vigenere Cipher - Encryption
# -----------------------------
def vigenere_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").lower()  # remove spaces and make lowercase
    key = key.lower()  # ensure key is lowercase
    ciphertext = ""  # to store encrypted text

    # loop through each character in plaintext
    for i, char in enumerate(plaintext):
        shift = (ord(key[i % len(key)]) - ord('a'))  # get shift value from key letter
        encrypted = (ord(char) - ord('a') + shift) % 26 + ord('a')  # apply shift
        ciphertext += chr(encrypted)  # convert back to letter and add
    return ciphertext


# -----------------------------
# Vigenere Cipher - Decryption
# -----------------------------
def vigenere_decrypt(ciphertext, key):
    key = key.lower()  # ensure key is lowercase
    plaintext = ""  # to store decrypted text

    # loop through each character in ciphertext
    for i, char in enumerate(ciphertext):
        shift = (ord(key[i % len(key)]) - ord('a'))  # get shift value from key letter
        decrypted = (ord(char) - ord('a') - shift) % 26 + ord('a')  # subtract shift
        plaintext += chr(decrypted)  # convert back to letter and add
    return plaintext


# -----------------------------
# Autokey Cipher - Encryption
# -----------------------------
def autokey_encrypt(plaintext, key):
    plaintext = plaintext.replace(" ", "").lower()  # remove spaces and make lowercase
    key_stream = [key]  # start key stream with numeric key
    ciphertext = ""  # to store encrypted text

    # loop through each character in plaintext
    for i, char in enumerate(plaintext):
        # use integer for first shift, then plaintext letters as key
        shift = key_stream[i] if isinstance(key_stream[i], int) else (ord(key_stream[i]) - ord('a'))
        encrypted = (ord(char) - ord('a') + shift) % 26 + ord('a')  # apply shift
        ciphertext += chr(encrypted)  # convert back to letter and add
        key_stream.append(char)  # add plaintext character to key
    return ciphertext


# -----------------------------
# Autokey Cipher - Decryption
# -----------------------------
def autokey_decrypt(ciphertext, key):
    plaintext = ""  # to store decrypted text
    key_stream = [key]  # start key stream with numeric key

    # loop through each character in ciphertext
    for i, char in enumerate(ciphertext):
        # use integer for first shift, then recovered plaintext letters as key
        shift = key_stream[i] if isinstance(key_stream[i], int) else (ord(key_stream[i]) - ord('a'))
        decrypted = (ord(char) - ord('a') - shift) % 26 + ord('a')  # subtract shift
        plain_char = chr(decrypted)  # convert back to letter
        plaintext += plain_char  # add to plaintext
        key_stream.append(plain_char)  # recovered plaintext becomes key
    return plaintext


# -----------------------------
# Test the Code
# -----------------------------
plain = "the house is being sold tonight"  # given message

print("Original:", plain)

# Vigenere Cipher Test
vig_enc = vigenere_encrypt(plain, "dollars")  # encrypt with key "dollars"
print("\nVigenere Encrypted:", vig_enc)
print("Vigenere Decrypted:", vigenere_decrypt(vig_enc, "dollars"))

# Autokey Cipher Test
auto_enc = autokey_encrypt(plain, 7)  # encrypt with numeric key 7
print("\nAutokey Encrypted:", auto_enc)
print("Autokey Decrypted:", autokey_decrypt(auto_enc, 7))
