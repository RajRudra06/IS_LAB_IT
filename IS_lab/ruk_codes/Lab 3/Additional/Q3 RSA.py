# Small-RSA example: encrypt/decrypt plaintext byte-by-byte using given (n,e,d)
# Note: this is educational only; real RSA uses padding + large moduli.

# Given RSA parameters (small numbers from question)
n = 323                                          # modulus
e = 5                                            # public exponent
d = 173                                          # private exponent

# plaintext to encrypt
plaintext = "Cryptographic Protocols"            # message string
pt_bytes = plaintext.encode('utf-8')             # convert to bytes

# Encrypt each byte as integer m^e mod n
cipher_bytes = []                                # store integer ciphertexts
for b in pt_bytes:                               # loop each byte
    c = pow(b, e, n)                             # ciphertext integer
    cipher_bytes.append(c)                       # append integer

# show first few ciphertext integers
print("Ciphertext integers (first 20):", cipher_bytes[:20])

# Decrypt each ciphertext integer using d
recovered = bytearray()                          # buffer for recovered bytes
for c in cipher_bytes:                           # iterate ciphertext integers
    m = pow(c, d, n)                             # decrypted integer (should equal original byte)
    recovered.append(m)                          # append as byte

# decode back to string
try:
    recovered_text = recovered.decode('utf-8')   # decode bytes to string
except Exception:
    recovered_text = None

# print recovered plaintext
print("Recovered plaintext:", recovered_text)
# sanity check: equality with original
print("Match original?", recovered_text == plaintext)
