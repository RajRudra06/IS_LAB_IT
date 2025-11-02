import string

# entire code platfair cipher

def create_playfair_matrix(key):
    key = "".join(dict.fromkeys(key.upper()))  # remove duplicates
    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"      # merge I/J
    matrix = []
    for c in key:
        if c in alphabet:
            matrix.append(c)
            alphabet = alphabet.replace(c, "")
    matrix.extend(alphabet)
    # make 5x5 matrix
    return [matrix[i*5:(i+1)*5] for i in range(5)]

def preprocess_text(text):
    text = text.upper().replace("J","I").replace(" ","")
    result = ""
    i = 0
    while i < len(text):
        a = text[i]
        b = text[i+1] if i+1 < len(text) else 'X'
        if a == b:
            result += a + 'X'
            i += 1
        else:
            result += a + b
            i += 2
    if len(result) %2 !=0:
        result += 'X'
    return result

def find_position(matrix, c):
    for i,row in enumerate(matrix):
        if c in row:
            return i,row.index(c)
    return None

def playfair_encrypt(text, matrix):
    ct = ""
    for i in range(0,len(text),2):
        a,b = text[i],text[i+1]
        ra,ca = find_position(matrix,a)
        rb,cb = find_position(matrix,b)
        if ra==rb:
            ct += matrix[ra][(ca+1)%5] + matrix[rb][(cb+1)%5]
        elif ca==cb:
            ct += matrix[(ra+1)%5][ca] + matrix[(rb+1)%5][cb]
        else:
            ct += matrix[ra][cb] + matrix[rb][ca]
    return ct

# Key and plaintext
key = "GUIDANCE"
plaintext = "The key is hidden under the door pad"

matrix = create_playfair_matrix(key)
processed_text = preprocess_text(plaintext)
ciphertext = playfair_encrypt(processed_text, matrix)

print("Playfair Matrix:")
for row in matrix:
    print(row)
print("\nProcessed plaintext:", processed_text)
print("Ciphertext:", ciphertext)
