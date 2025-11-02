# menu_rsa_aes.py
# A simple menu-driven CLI demonstrating structure and a hybrid RSA+AES example.
# Every line below has a comment explaining what it does.

# ----- imports -----
from Crypto.PublicKey import RSA                       # RSA key generation & public key objects
from Crypto.Cipher import PKCS1_OAEP, AES              # RSA-OAEP for key transport, AES for symmetric encryption (GCM)
from Crypto.Random import get_random_bytes             # secure random bytes generator for AES keys/nonces
import base64                                          # for compact printable representation of binary data
import sys                                             # for clean exit
import time                                            # for optional timing

# ----- small helpers -----
def b64encode(b: bytes) -> str:
    # Return base64 string for given bytes (safe for printing).
    return base64.b64encode(b).decode('ascii')

def b64decode(s: str) -> bytes:
    # Decode base64 string back to bytes; caller should handle exceptions if invalid.
    return base64.b64decode(s.encode('ascii'))

# ----- crypto helpers -----
def generate_rsa(bits: int = 2048):
    # Generate an RSA private key and return (priv_obj, pub_obj).
    key = RSA.generate(bits)                            # create private key
    return key, key.publickey()                         # return private and public

def hybrid_encrypt(plaintext: str, recipient_pub):
    # Hybrid encrypt: AES-GCM for message, RSA-OAEP encrypts AES key.
    pt = plaintext.encode('utf-8')                      # encode plaintext string to bytes
    aes_key = get_random_bytes(32)                      # create AES-256 key (32 bytes)
    nonce = get_random_bytes(12)                        # 12-byte nonce for AES-GCM
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)   # create AES-GCM cipher object
    ciphertext, tag = aes.encrypt_and_digest(pt)        # encrypt and produce authentication tag
    rsa_cipher = PKCS1_OAEP.new(recipient_pub)          # OAEP cipher with recipient's public key
    enc_key = rsa_cipher.encrypt(aes_key)               # RSA-encrypt the AES key
    # pack everything into a dict of base64 strings for convenience/transmission
    package = {
        'enc_key_b64': b64encode(enc_key),
        'nonce_b64': b64encode(nonce),
        'tag_b64': b64encode(tag),
        'ciphertext_b64': b64encode(ciphertext)
    }
    return package                                      # return the encrypted package

def hybrid_decrypt(package: dict, recipient_priv):
    # Hybrid decrypt: RSA-OAEP decrypt AES key, then AES-GCM decrypt ciphertext.
    enc_key = b64decode(package['enc_key_b64'])        # decode RSA-encrypted AES key
    nonce = b64decode(package['nonce_b64'])            # decode nonce
    tag = b64decode(package['tag_b64'])                # decode tag
    ciphertext = b64decode(package['ciphertext_b64'])  # decode ciphertext
    rsa_dec = PKCS1_OAEP.new(recipient_priv)           # OAEP object with private key
    aes_key = rsa_dec.decrypt(enc_key)                 # recover AES key (bytes)
    aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)  # AES-GCM object for decryption
    plaintext_bytes = aes.decrypt_and_verify(ciphertext, tag)  # decrypt and verify
    return plaintext_bytes.decode('utf-8')             # return string

# ----- UI action functions -----
def action_generate_key(state: dict):
    # Generate RSA keypair and store in provided state dict.
    bits = input("Enter RSA key size in bits [2048]: ").strip()  # ask user for size
    if bits == "":                                             # if empty use default
        bits_int = 2048
    else:
        try:
            bits_int = int(bits)                                # convert to integer
        except ValueError:
            print("Invalid integer, using default 2048.")      # fallback on bad input
            bits_int = 2048
    print("Generating RSA keypair, this may take a moment...")
    t0 = time.perf_counter()                                    # start timer
    priv, pub = generate_rsa(bits_int)                          # call generator
    t1 = time.perf_counter()                                    # end timer
    state['rsa_priv'] = priv                                    # save private key in state
    state['rsa_pub'] = pub                                      # save public key
    print(f"RSA-{bits_int} keypair generated in {(t1-t0)*1000:.1f} ms.")

def action_show_public_key(state: dict):
    # Print the public key PEM (or tell the user none exists).
    pub = state.get('rsa_pub')
    if not pub:
        print("No public key found. Generate keys first.")
        return
    pem = pub.export_key().decode('ascii')                      # export PEM text
    print("\n----- Public Key PEM -----")
    print(pem)
    print("--------------------------\n")

def action_encrypt_message(state: dict):
    # Encrypt a plaintext with the stored public key and display package.
    pub = state.get('rsa_pub')
    if not pub:
        print("No public key present. Generate keys first.")
        return
    plaintext = input("Enter plaintext to encrypt: ")            # read plaintext string
    if plaintext.strip() == "":
        print("Empty message — aborting encryption.")
        return
    package = hybrid_encrypt(plaintext, pub)                    # perform hybrid encryption
    # pretty print package base64 lengths and truncated fields
    print("Encrypted package (base64):")
    print(" enc_key:", package['enc_key_b64'][:60] + "...")
    print(" nonce:  ", package['nonce_b64'])
    print(" tag:    ", package['tag_b64'])
    print(" ciphertext (prefix):", package['ciphertext_b64'][:80] + "...")
    # store last package so user can decrypt without manual copy/paste
    state['last_package'] = package

def action_decrypt_message(state: dict):
    # Decrypt the stored package or allow pasting a package manually.
    priv = state.get('rsa_priv')
    if not priv:
        print("No private key present. Generate keys first.")
        return
    pkg = state.get('last_package')
    if not pkg:
        choice = input("No stored package. Paste JSON-like package? (y/N): ").strip().lower()
        if choice != 'y':
            print("Nothing to decrypt.")
            return
        # prompt user to paste the 4 base64 fields sequentially
        enc_key_b64 = input("Paste enc_key (base64): ").strip()
        nonce_b64 = input("Paste nonce (base64): ").strip()
        tag_b64 = input("Paste tag (base64): ").strip()
        ciphertext_b64 = input("Paste ciphertext (base64): ").strip()
        pkg = {
            'enc_key_b64': enc_key_b64,
            'nonce_b64': nonce_b64,
            'tag_b64': tag_b64,
            'ciphertext_b64': ciphertext_b64
        }
    try:
        plaintext = hybrid_decrypt(pkg, priv)                    # attempt decryption
        print("Decrypted plaintext:")
        print(plaintext)
    except Exception as e:
        # catch generic exceptions to show a friendly message (in real code narrow the exceptions)
        print("Decryption failed (bad package, wrong key, or tampering).")
        print("Error:", str(e))

def action_quit(state: dict):
    # Set a flag to break the main loop and exit program.
    state['running'] = False
    print("Exiting program... Goodbye.")

# ----- menu dispatch table mapping option numbers to (label, function) -----
MENU = {
    '1': ("Generate RSA keypair", action_generate_key),
    '2': ("Show public key (PEM)", action_show_public_key),
    '3': ("Encrypt a message (hybrid RSA+AES)", action_encrypt_message),
    '4': ("Decrypt last or pasted package", action_decrypt_message),
    '5': ("Quit", action_quit)
}

# ----- main loop / entrypoint -----
def main():
    # state dict holds in-memory keys and last package; in production use secure storage
    state = {'rsa_priv': None, 'rsa_pub': None, 'last_package': None, 'running': True}
    # loop until the user picks Quit (action_quit sets state['running']=False)
    while state['running']:
        # print menu options
        print("\n=== Simple Hybrid RSA+AES Menu ===")
        for key, (label, _) in MENU.items():                   # iterate in dict order (py3.7+ preserves insertion)
            print(f"{key}. {label}")
        choice = input("Select an option: ").strip()           # read user choice
        # validate and dispatch
        action = MENU.get(choice)
        if not action:
            print("Invalid choice — please enter the number of an option.")
            continue                                           # restart loop for another attempt
        # call the selected function with the shared state
        _, func = action
        try:
            func(state)                                       # functions modify state as required
        except KeyboardInterrupt:
            # allow user to cancel a long-running operation with Ctrl+C without killing program
            print("\nOperation cancelled by user (Ctrl+C). Returning to menu.")
        except Exception as e:
            # catch unexpected errors and continue rather than crash; print for debugging in lab
            print("An error occurred while performing the operation:", str(e))

# run the main loop when invoked directly
if __name__ == "__main__":
    main()                                                    # start menu-driven CLI
