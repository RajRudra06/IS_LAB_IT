from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from time import time

# Messages to encrypt
messages = [
    b"Message number one",
    b"Message number two",
    b"Message number three",
    b"Message number four",
    b"Message number five"
]

# Correct AES and DES keys
key_des = b"8bytekey"  # DES = 8 bytes
key_aes_128 = b"1234567890ABCDEF"  # 16 bytes
key_aes_192 = b"1234567890ABCDEFGHIJKL12"  # 24 bytes
key_aes_256 = b"1234567890ABCDEFGHIJKLMNOPQRSTUV"  # 32 bytes

# AES modes
modes = {
    "ECB": AES.MODE_ECB,
    "CBC": AES.MODE_CBC,
    "CFB": AES.MODE_CFB,
    "OFB": AES.MODE_OFB
}

# Store results
results = {"DES": {}, "AES-128": {}, "AES-192": {}, "AES-256": {}}

# Helper: measure encryption time
def measure_encryption_time(algorithm_name, cipher_func, mode_name):
    start = time()
    for msg in messages:
        cipher_func(msg)
    end = time()
    elapsed = end - start
    results[algorithm_name][mode_name] = elapsed

# DES encryption (ECB, CBC)
for mode_name in ["ECB", "CBC"]:
    def des_encrypt(msg, mode_name=mode_name):
        if mode_name == "ECB":
            cipher = DES.new(key_des, DES.MODE_ECB)
        else:
            iv = b"12345678"
            cipher = DES.new(key_des, DES.MODE_CBC, iv)
        return cipher.encrypt(pad(msg, DES.block_size))
    measure_encryption_time("DES", des_encrypt, mode_name)

# AES encryption (128, 192, 256 bits)
for key, label in [(key_aes_128, "AES-128"), (key_aes_192, "AES-192"), (key_aes_256, "AES-256")]:
    for mode_name, mode_value in modes.items():
        def aes_encrypt(msg, key=key, mode=mode_value):
            iv = b"1234567890ABCDEF" if mode != AES.MODE_ECB else None
            cipher = AES.new(key, mode, iv) if iv else AES.new(key, mode)
            return cipher.encrypt(pad(msg, AES.block_size))
        measure_encryption_time(label, aes_encrypt, mode_name)

# Print results
for algo, times in results.items():
    print(f"\n{algo} Encryption Times:")
    for mode, elapsed in times.items():
        print(f"  {mode}: {elapsed:.6f} seconds")
