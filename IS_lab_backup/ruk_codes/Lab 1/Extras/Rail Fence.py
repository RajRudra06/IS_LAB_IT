"""
Rail Fence Cipher implementation in Python
- Works with any number of rails (rows).
- Provides encrypt() and decrypt() functions.
"""


# Function to encrypt plaintext using Rail Fence Cipher
def rail_fence_encrypt(plaintext, rails):
    # remove spaces for simplicity
    plaintext = plaintext.replace(" ", "")

    # create a list of strings, one for each rail
    fence = ['' for _ in range(rails)]

    row, step = 0, 1  # start from top rail, moving down
    for char in plaintext:
        fence[row] += char
        # change direction if we hit top or bottom rail
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    # join all rows to form ciphertext
    return ''.join(fence)


# Function to decrypt ciphertext using Rail Fence Cipher
def rail_fence_decrypt(ciphertext, rails):
    # length of ciphertext
    length = len(ciphertext)
    # mark zigzag positions
    marker = [['\n' for _ in range(length)] for _ in range(rails)]

    row, step = 0, 1
    for i in range(length):
        marker[row][i] = '*'
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step

    # fill ciphertext characters into marker
    index = 0
    for r in range(rails):
        for c in range(length):
            if marker[r][c] == '*' and index < length:
                marker[r][c] = ciphertext[index]
                index += 1

    # now read zigzag to reconstruct plaintext
    result = []
    row, step = 0, 1
    for i in range(length):
        result.append(marker[row][i])
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step

    return ''.join(result)


# ---------------------------
# Example usage
# ---------------------------
if __name__ == "__main__":
    text = "TopSecretData"
    rails = 5

    cipher = rail_fence_encrypt(text, rails)
    print("Plaintext:", text)
    print("Encrypted (ciphertext):", cipher)

    recovered = rail_fence_decrypt(cipher, rails)
    print("Decrypted (recovered):", recovered)
