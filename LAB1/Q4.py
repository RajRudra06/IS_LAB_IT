import numpy as np

# 2x2 Hill cipher key
K = np.array([[3,3],
              [2,7]])

# plaintext preprocessing
pt = "We live in an insecure world".replace(" ","").lower()
# pad if odd
if len(pt)%2 != 0:
    pt += "x"

# convert to numbers
pt_nums = [ord(c)-ord('a') for c in pt]

# split into 2-letter blocks
blocks = [pt_nums[i:i+2] for i in range(0,len(pt_nums),2)]

# encrypt blocks
ct_nums = []
for b in blocks:
    vec = np.array(b)
    enc = K.dot(vec)%26
    ct_nums.extend(enc.tolist())

# convert back to letters
ct = ''.join(chr(n+ord('a')) for n in ct_nums)
print("Ciphertext:", ct)
