# Simple Menu Driven Program for Rail Fence and Columnar Transposition Cipher

import math

# ---- Rail Fence Cipher ----
def rail_fence_encrypt(text, rails):
    text = text.replace(" ", "").upper()
    fence = ['' for _ in range(rails)]
    row, step = 0, 1
    for ch in text:
        fence[row] += ch
        if row == 0:
            step = 1
        elif row == rails - 1:
            step = -1
        row += step
    return ''.join(fence)

def rail_fence_decrypt(cipher, rails):
    cipher = cipher.replace(" ", "").upper()
    length = len(cipher)
    marker = [['' for _ in range(length)] for _ in range(rails)]
    row, step = 0, 1
    for i in range(length):
        marker[row][i] = '*'
        if row == 0: step = 1
        elif row == rails-1: step = -1
        row += step
    idx = 0
    for r in range(rails):
        for c in range(length):
            if marker[r][c] == '*' and idx < length:
                marker[r][c] = cipher[idx]
                idx += 1
    result = []
    row, step = 0, 1
    for i in range(length):
        result.append(marker[row][i])
        if row == 0: step = 1
        elif row == rails-1: step = -1
        row += step
    return ''.join(result)

# ---- Columnar Transposition ----
def columnar_encrypt(text, key):
    text = text.replace(" ", "").upper()
    key = key.upper()
    cols = len(key)
    rows = math.ceil(len(text) / cols)
    text = text.ljust(rows*cols, 'X')
    grid = [text[i*cols:(i+1)*cols] for i in range(rows)]
    order = sorted(list(enumerate(key)), key=lambda x: (x[1], x[0]))
    cipher = ''
    for idx, _ in order:
        for row in grid:
            cipher += row[idx]
    return cipher

def columnar_decrypt(cipher, key):
    cipher = cipher.replace(" ", "").upper()
    key = key.upper()
    cols = len(key)
    rows = math.ceil(len(cipher) / cols)
    order = sorted(list(enumerate(key)), key=lambda x: (x[1], x[0]))
    grid = [['' for _ in range(cols)] for _ in range(rows)]
    idx = 0
    for col_idx, _ in order:
        for r in range(rows):
            if idx < len(cipher):
                grid[r][col_idx] = cipher[idx]
                idx += 1
    plain = ''.join(''.join(row) for row in grid)
    return plain.rstrip('X')

# ---- Menu ----
def menu():
    print("\n=== MENU ===")
    print("1. Rail Fence Encrypt")
    print("2. Rail Fence Decrypt")
    print("3. Columnar Encrypt")
    print("4. Columnar Decrypt")
    print("5. Quit")

while(1):
    menu()
    choice = input("Enter your choice: ")

    if choice == '1':
        text = input("Enter plaintext: ")
        rails = int(input("Enter number of rails: "))
        print("Ciphertext:", rail_fence_encrypt(text, rails))

    elif choice == '2':
        cipher = input("Enter ciphertext: ")
        rails = int(input("Enter number of rails: "))
        print("Plaintext:", rail_fence_decrypt(cipher, rails))

    elif choice == '3':
        text = input("Enter plaintext: ")
        key = input("Enter key (word): ")
        print("Ciphertext:", columnar_encrypt(text, key))

    elif choice == '4':
        cipher = input("Enter ciphertext: ")
        key = input("Enter key (word): ")
        print("Plaintext:", columnar_decrypt(cipher, key))

    elif choice == '5':
        print("Exiting program...")
        break

    else:
        print("Invalid choice, try again.")
