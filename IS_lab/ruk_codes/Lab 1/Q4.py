# import numpy to help with vector/matrix multiplication
import numpy as np

# ----------------------------
# Helper: extended gcd to find modular inverse
# ----------------------------
def egcd(a, b):
    # extended Euclidean algorithm returns (g, x, y) with ax + by = g = gcd(a,b)
    if a == 0:
        return (b, 0, 1)               # base case
    else:
        g, x1, y1 = egcd(b % a, a)    # recurse
        x = y1 - (b // a) * x1        # update x
        y = x1                        # update y
        return (g, x, y)              # return gcd and coefficients

def modinv(a, m):
    # compute modular inverse of a modulo m, if it exists
    g, x, _ = egcd(a % m, m)         # get gcd and x
    if g != 1:                       # inverse exists only if gcd == 1
        return None                  # no inverse
    else:
        return x % m                 # return positive inverse modulo m

# ----------------------------
# Preprocessing and conversion helpers
# ----------------------------
def preprocess_text(text):
    # remove spaces and convert to lowercase
    text = text.lower().replace(" ", "")
    # if length is odd, append 'x' to make it even (Hill uses fixed block size 2)
    if len(text) % 2 != 0:
        text += 'x'
    return text                       # return normalized text

def text_to_numbers(text):
    # convert letters to numbers: 'a' -> 0, ..., 'z' -> 25
    return [ord(ch) - ord('a') for ch in text]

def numbers_to_text(nums):
    # convert numbers back to letters
    return ''.join(chr(int(n) + ord('a')) for n in nums)

# ----------------------------
# Hill cipher encryption (2x2)
# ----------------------------
def hill_encrypt(plaintext, key_matrix):
    # preprocess plaintext (remove spaces, lowercase, make even length)
    pt = preprocess_text(plaintext)
    # convert preprocessed plaintext to list of numbers
    nums = text_to_numbers(pt)
    # list to hold resulting cipher numbers
    cipher_nums = []
    # ensure key_matrix is a numpy array of ints
    K = np.array(key_matrix, dtype=int)
    # iterate over plaintext numbers two at a time (block size = 2)
    for i in range(0, len(nums), 2):
        pair = np.array(nums[i:i+2], dtype=int)   # take two numbers as a column vector
        # matrix multiply K * pair (treat pair as column); use mod 26
        enc = (K.dot(pair) % 26).astype(int)
        # append both numbers of the encrypted block to result
        cipher_nums.extend(enc.tolist())
    # convert number list back to letters and return ciphertext
    return numbers_to_text(cipher_nums)

# ----------------------------
# Hill cipher decryption (2x2)
# ----------------------------
def hill_decrypt(ciphertext, key_matrix):
    # convert key matrix to integer numpy array
    K = np.array(key_matrix, dtype=int)
    # compute determinant (integer arithmetic) for 2x2: det = a*d - b*c
    a, b = int(K[0,0]), int(K[0,1])
    c, d = int(K[1,0]), int(K[1,1])
    det = (a * d - b * c) % 26                # determinant mod 26
    # compute modular inverse of determinant modulo 26
    det_inv = modinv(det, 26)                 # modular inverse of det mod 26
    if det_inv is None:
        raise ValueError("Key matrix is not invertible modulo 26; cannot decrypt.")
    # compute adjugate matrix for 2x2: [[d, -b], [-c, a]]
    adj = np.array([[ d, -b],
                    [-c,  a]], dtype=int)
    # multiply adjugate by det_inv and reduce mod 26 to get inverse matrix modulo 26
    K_inv = (det_inv * adj) % 26
    # convert ciphertext to numbers
    nums = text_to_numbers(ciphertext.lower())
    # list to hold decrypted numbers
    plain_nums = []
    # process ciphertext two numbers at a time
    for i in range(0, len(nums), 2):
        pair = np.array(nums[i:i+2], dtype=int)   # take two numbers as column vector
        # multiply inverse key with pair modulo 26
        dec = (K_inv.dot(pair) % 26).astype(int)
        # append recovered plaintext numbers
        plain_nums.extend(dec.tolist())
    # convert numbers back to letters and return plaintext
    return numbers_to_text(plain_nums)

# ----------------------------
# Test the encryption & decryption
# ----------------------------

# define the 2x2 key matrix K = [[3,3],[2,7]] as given in the question
K = [[3, 3],
     [2, 7]]

# the message to encrypt
message = "We live in an insecure world"

# encrypt the message with Hill cipher
cipher = hill_encrypt(message, K)
# print original and encrypted text
print("Original message:", message)
print("Encrypted message:", cipher)

# decrypt the ciphertext back using the same key
decrypted = hill_decrypt(cipher, K)
# print decrypted text (note: spaces are not restored by this simple routine)
print("Decrypted message:", decrypted)
