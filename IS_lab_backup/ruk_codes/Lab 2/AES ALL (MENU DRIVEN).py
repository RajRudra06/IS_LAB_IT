# import AES algorithm and padding helpers from pycryptodome
from Crypto.Cipher import AES                                  # AES block cipher
from Crypto.Util.Padding import pad, unpad                      # PKCS#7 padding helpers
from Crypto.Random import get_random_bytes                      # secure random IV generator
import sys                                                      # to allow clean exit

# function to normalize or build a key of required length (16,24,32)
def build_key_from_string(key_str, required_len):
    key_str = key_str.encode('utf-8')                           # convert provided key string to bytes
    if len(key_str) == required_len:                            # if already correct length
        return key_str                                           # return as-is
    if len(key_str) > required_len:                             # if longer than required
        return key_str[:required_len]                            # truncate to required length
    # if shorter than required, pad by repeating the key and then truncating
    repeated = (key_str * ((required_len // len(key_str)) + 1))  # repeat enough times
    return repeated[:required_len]                               # then cut to required_len

# function to perform AES encryption in CBC mode and return hex ciphertext (IV prepended)
def aes_encrypt(message_text, key_bytes):
    message_bytes = message_text.encode('utf-8')                 # convert plaintext to bytes
    iv = get_random_bytes(16)                                    # generate a random 16-byte IV
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)                # create AES-CBC cipher with key and IV
    ct_bytes = cipher.encrypt(pad(message_bytes, AES.block_size))# pad plaintext and encrypt
    combined = iv + ct_bytes                                     # prepend IV to ciphertext for transport
    return combined.hex()                                        # return combined IV+ciphertext as hex string

# function to perform AES decryption in CBC mode given hex input (expects IV prepended)
def aes_decrypt(hex_ciphertext, key_bytes):
    combined = bytes.fromhex(hex_ciphertext)                     # convert hex string back to bytes
    if len(combined) < 16:                                       # must have at least IV length
        raise ValueError("Ciphertext too short (missing IV).")   # raise helpful error if too short
    iv = combined[:16]                                           # extract first 16 bytes as IV
    ct_bytes = combined[16:]                                     # the rest is the actual ciphertext
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)                # create AES-CBC cipher with same IV and key
    pt_padded = cipher.decrypt(ct_bytes)                         # decrypt ciphertext to padded plaintext
    plaintext_bytes = unpad(pt_padded, AES.block_size)           # remove PKCS#7 padding
    return plaintext_bytes.decode('utf-8')                       # decode bytes back to string and return

# print a simple menu for the user
def print_menu():
    print("\nAES Menu:")                                          # header
    print("1) Encrypt (AES-128)")                                 # option for AES-128 encryption
    print("2) Encrypt (AES-192)")                                 # option for AES-192 encryption
    print("3) Encrypt (AES-256)")                                 # option for AES-256 encryption
    print("4) Decrypt (AES-128)")                                 # option for AES-128 decryption
    print("5) Decrypt (AES-192)")                                 # option for AES-192 decryption
    print("6) Decrypt (AES-256)")                                 # option for AES-256 decryption
    print("0) Exit")                                              # exit option

# main interactive loop
def main():
    while True:                                                  # loop until user chooses to exit
        print_menu()                                             # display menu each iteration
        choice = input("Choose an option (0-6): ").strip()       # get user choice from input
        if choice == '0':                                        # if user chose exit
            print("Exiting...")                                  # inform and
            sys.exit(0)                                          # exit program cleanly

        # map numeric choices to required AES key length in bytes
        choice_to_keylen = {'1':16, '2':24, '3':32, '4':16, '5':24, '6':32}
        if choice not in choice_to_keylen:                       # validate choice
            print("Invalid option. Please choose 0-6.")          # print error and restart loop
            continue

        key_len = choice_to_keylen[choice]                       # determine required key length

        # ask user for the key string and build the key of correct length
        user_key_str = input(f"Enter key string (will be adjusted to {key_len} bytes): ").strip()
        key_bytes = build_key_from_string(user_key_str, key_len) # create key bytes of required length

        # Encryption branch (1-3)
        if choice in ('1', '2', '3'):
            plaintext = input("Enter plaintext to encrypt: ")    # get plaintext from user
            try:                                                 # try/except to catch any errors during encryption
                cipher_hex = aes_encrypt(plaintext, key_bytes)   # perform encryption and get hex output
                print("\nEncrypted output (hex, IV prepended):") # label for output
                print(cipher_hex)                               # show hex ciphertext (IV + ciphertext)
            except Exception as e:                               # catch exceptions and display message
                print("Encryption error:", str(e))              # display error message

        # Decryption branch (4-6)
        else:
            cipher_hex = input("Enter hex ciphertext (IV must be prepended): ").strip() # ask for hex ciphertext
            try:                                                 # try/except to handle decryption errors
                decrypted = aes_decrypt(cipher_hex, key_bytes)   # attempt decrypt using supplied key
                print("\nDecrypted plaintext:")                  # label
                print(decrypted)                                 # print the recovered plaintext
            except Exception as e:                               # handle errors (bad key/invalid hex/padding)
                print("Decryption error:", str(e))               # show helpful error

# program entrypoint check
if __name__ == "__main__":                                      # ensure script is run directly
    main()                                                       # call main loop to start program
