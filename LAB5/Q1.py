def custom_hash(input_string):
    hash_value = 5381  # initial hash value
    
    for ch in input_string:
        # Multiply by 33 and add ASCII value of current character
        hash_value = ((hash_value * 33) + ord(ch)) & 0xFFFFFFFF  # keep within 32 bits
    
    return hash_value

# Example
text = "Asymmetric Encryption"
result = custom_hash(text)
print("Input:", text)
print("Hash value:", result)

# With lib

import hashlib

text = "Asymmetric Encryption"
hash_value = hashlib.sha256(text.encode('utf-8')).hexdigest()

print("Input:", text)
print("SHA-256 Hash:", hash_value)
