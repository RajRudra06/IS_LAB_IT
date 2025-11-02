def additive_bruteforce(cipher):
    for key in range(26):
        plain = "".join([chr(((ord(c)-97-key)%26)+97) for c in cipher.lower()])
        print(f"Key={key}: {plain}")

cipher = "NCJAEZRCLASLYODEPRLYZRCLASJLCPEHZDTOPDZOLNBY".lower()
additive_bruteforce(cipher)
