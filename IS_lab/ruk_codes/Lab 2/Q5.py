# ---------------------------
# AES-192: Full step-by-step demonstration
# - shows key expansion, initial round, main rounds, final round
# - every line commented
# ---------------------------

# import required libraries for final verification and padding
from Crypto.Cipher import AES                         # AES implementation for verification
from Crypto.Util.Padding import pad, unpad             # padding helpers
import binascii                                        # hex printing helper

# ---------------------------
# AES S-box (256 entries) for SubBytes/SubWord
# ---------------------------
s_box = [                                             # AES S-box table (0..255)
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]                                                     # end S-box

# ---------------------------
# Rcon table for key schedule (enough entries for AES-192 rounds)
# ---------------------------
Rcon = [0x00000000,0x01000000,0x02000000,0x04000000,0x08000000,0x10000000,
        0x20000000,0x40000000,0x80000000,0x1b000000,0x36000000]  # round constants

# ---------------------------
# 4-byte word helpers for key schedule
# ---------------------------
def bytes_to_word(b0, b1, b2, b3):
    # pack 4 bytes into 32-bit word (big-endian)
    return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3

def word_to_bytes(word):
    # unpack 32-bit word to 4 bytes (big-endian)
    return [(word >> 24) & 0xff, (word >> 16) & 0xff, (word >> 8) & 0xff, word & 0xff]

def rot_word(word):
    # rotate 4-byte word left by one byte
    b = word_to_bytes(word)
    return bytes_to_word(b[1], b[2], b[3], b[0])

def sub_word(word):
    # substitute each byte of the word using AES S-box
    b = word_to_bytes(word)
    return bytes_to_word(s_box[b[0]], s_box[b[1]], s_box[b[2]], s_box[b[3]])

# ---------------------------
# Key expansion for AES-192 (produces round keys as 16-byte blocks)
# ---------------------------
def key_expansion_192(key_bytes):
    # Nk = 6 words (24 bytes), Nb = 4, Nr = 12 rounds for AES-192
    Nk = 6
    Nb = 4
    Nr = 12
    # initial words W[0..Nk-1] from key
    W = []
    for i in range(Nk):
        w = bytes_to_word(key_bytes[4*i], key_bytes[4*i+1], key_bytes[4*i+2], key_bytes[4*i+3])
        W.append(w)
    # expand to total_words = Nb*(Nr+1)
    total_words = Nb * (Nr + 1)
    i = Nk
    rcon_iter = 1
    while i < total_words:
        temp = W[i-1]
        if i % Nk == 0:
            # every Nk words: RotWord, SubWord, XOR with Rcon
            temp = sub_word(rot_word(temp)) ^ Rcon[rcon_iter]
            rcon_iter += 1
        elif Nk > 6 and i % Nk == 4:
            # branch used for AES-256 (not applicable for 192) kept for completeness
            temp = sub_word(temp)
        # W[i] = W[i-Nk] XOR temp
        W.append(W[i-Nk] ^ temp)
        i += 1
    # pack words into round keys (each round key is 4 words = 16 bytes)
    round_keys = []
    for r in range(Nr + 1):
        start = r * Nb
        block_bytes = []
        for j in range(Nb):
            block_bytes.extend(word_to_bytes(W[start + j]))
        round_keys.append(bytes(block_bytes))
    return round_keys  # list of 13 round keys (round 0..12)

# ---------------------------
# AES state helpers (state is 4x4 bytes, column-major)
# ---------------------------
def bytes_to_state(block):
    # convert 16-byte block to 4x4 state (list of 4 columns each with 4 bytes)
    # AES uses column-major order: state[c][r] = block[4*c + r]
    state = [[0]*4 for _ in range(4)]  # create 4 columns x 4 rows
    for c in range(4):
        for r in range(4):
            state[c][r] = block[4*c + r]
    return state

def state_to_bytes(state):
    # convert state back to 16-byte block in column-major ordering
    out = []
    for c in range(4):
        for r in range(4):
            out.append(state[c][r] & 0xff)
    return bytes(out)

def print_state(label, state):
    # print a state with label in hex (showing columns)
    b = state_to_bytes(state)                 # convert to bytes
    print(f"{label}: {b.hex()}")              # print hex representation

# ---------------------------
# AES round operations
# ---------------------------
def sub_bytes(state):
    # apply S-box to every byte in state
    for c in range(4):
        for r in range(4):
            state[c][r] = s_box[state[c][r]]

def shift_rows(state):
    # perform row shifts (row 0 none, row1 shift left 1, row2 shift left 2, row3 shift left 3)
    # convert to row view for convenience
    rows = [[state[c][r] for c in range(4)] for r in range(4)]
    for r in range(1,4):
        # left rotate row r by r positions
        rows[r] = rows[r][r:] + rows[r][:r]
    # write rows back into column-major state
    for c in range(4):
        for r in range(4):
            state[c][r] = rows[r][c]

# finite field multiplication helper (GF(2^8)) for MixColumns
def xtime(a):
    # multiply by x (i.e., {02}) in GF(2^8)
    return ((a << 1) ^ 0x1b) & 0xff if (a & 0x80) else (a << 1) & 0xff

def mul(a, b):
    # multiply two bytes in GF(2^8) using Russian peasant multiplication
    result = 0
    for i in range(8):
        if b & 1:
            result ^= a
        high_bit = a & 0x80
        a = (a << 1) & 0xff
        if high_bit:
            a ^= 0x1b
        b >>= 1
    return result

def mix_single_column(col):
    # mix one column (4 bytes) using AES mix columns matrix multiplication
    a0, a1, a2, a3 = col[0], col[1], col[2], col[3]
    col[0] = (mul(0x02, a0) ^ mul(0x03, a1) ^ a2 ^ a3) & 0xff
    col[1] = (a0 ^ mul(0x02, a1) ^ mul(0x03, a2) ^ a3) & 0xff
    col[2] = (a0 ^ a1 ^ mul(0x02, a2) ^ mul(0x03, a3)) & 0xff
    col[3] = (mul(0x03, a0) ^ a1 ^ a2 ^ mul(0x02, a3)) & 0xff

def mix_columns(state):
    # apply mix to each of the 4 columns
    for c in range(4):
        col = [state[c][r] for r in range(4)]
        mix_single_column(col)
        for r in range(4):
            state[c][r] = col[r]

def add_round_key(state, round_key_bytes):
    # XOR the 16-byte round key into the state
    rk_state = bytes_to_state(round_key_bytes)
    for c in range(4):
        for r in range(4):
            state[c][r] ^= rk_state[c][r]

# ---------------------------
# Main demonstration flow
# ---------------------------
# provided plaintext and key-string in problem
plaintext_str = "Top Secret Data"                        # given message
key_str = "FEDCBA9876543210FEDCBA9876543210"            # given key string

# prepare key bytes: interpret key_str as ASCII bytes and take first 24 bytes for AES-192
key_bytes_raw = key_str.encode('utf-8')                 # ascii bytes
if len(key_bytes_raw) < 24:
    key_bytes = key_bytes_raw.ljust(24, b'0')           # pad if shorter (not expected here)
else:
    key_bytes = key_bytes_raw[:24]                      # take first 24 bytes

# print chosen key bytes (hex) so you can see exact key used
print("AES-192 key (24 bytes hex):", key_bytes.hex())

# compute round keys via key expansion
round_keys = key_expansion_192(list(key_bytes))         # list of 13 round keys (round 0..12)

# print all round keys in hex with labels
print("\nRound keys (16 bytes each):")
for idx, rk in enumerate(round_keys):
    print(f"Round {idx:2d} key: {rk.hex()}")            # show round index and hex

# prepare plaintext: convert to bytes and pad to 16 bytes (AES block)
pt_bytes = plaintext_str.encode('utf-8')                # bytes of plaintext
pt_padded = pad(pt_bytes, AES.block_size)               # PKCS#7 padding to 16 bytes
print("\nPlaintext (utf-8):", plaintext_str)             # print plaintext
print("Padded plaintext (hex):", pt_padded.hex())        # print padded block in hex

# get single 16-byte block to encrypt
block = pt_padded[:16]                                  # AES block to operate on (one block here)

# convert block to AES state (column-major)
state = bytes_to_state(block)                           # initial state from plaintext block

# Initial AddRoundKey (round 0)
print("\n=== Initial AddRoundKey (Round 0) ===")
print_state("State before AddRoundKey", state)          # state before XOR
add_round_key(state, round_keys[0])                     # XOR round 0 key
print_state("State after AddRoundKey (round 0)", state) # show result

# Number of rounds for AES-192
Nr = 12

# Main rounds 1 .. Nr-1 (i.e., 1..11) with SubBytes, ShiftRows, MixColumns, AddRoundKey
for r in range(1, Nr):
    print(f"\n--- Round {r} ---")                        # label current round
    # SubBytes
    sub_bytes(state)                                    # S-box on each byte
    print_state("After SubBytes", state)                # print state
    # ShiftRows
    shift_rows(state)                                   # row shifts
    print_state("After ShiftRows", state)               # print state
    # MixColumns
    mix_columns(state)                                  # mix columns
    print_state("After MixColumns", state)              # print state
    # AddRoundKey
    add_round_key(state, round_keys[r])                 # XOR round key
    print_state(f"After AddRoundKey (round {r})", state) # print state

# Final round Nr (no MixColumns)
print(f"\n=== Final Round {Nr} ===")
sub_bytes(state)                                        # SubBytes
print_state("After SubBytes (final)", state)            # print
shift_rows(state)                                       # ShiftRows
print_state("After ShiftRows (final)", state)           # print
add_round_key(state, round_keys[Nr])                    # AddRoundKey with final round key
print_state("After AddRoundKey (final)", state)         # final state

# final ciphertext block produced by our step-by-step process
final_block = state_to_bytes(state)                     # convert state to 16-byte block
print("\nFinal ciphertext (hex) from step-by-step:", final_block.hex())

# ---------------------------
# Verify using pycryptodome AES-192 encrypt
# ---------------------------
cipher_verify = AES.new(key_bytes, AES.MODE_ECB)        # AES-192 cipher object in ECB mode
ct_verify = cipher_verify.encrypt(block)                # encrypt the same block
print("Ciphertext (hex) from pycryptodome AES-192:", ct_verify.hex())

# check equality and print verification result
if final_block == ct_verify:
    print("\nVerification: OK — step-by-step result matches library AES-192 output.")
else:
    print("\nVerification: MISMATCH — step-by-step result differs from library output.")
    # if mismatch occurs, show both values for debugging
    print("Step-by-step:", final_block.hex())
    print("Library     :", ct_verify.hex())
