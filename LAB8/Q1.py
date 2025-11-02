# Lab Exercise 1: Symmetric Searchable Encryption (SSE)
# ------------------------------------------------------

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import hashlib

# ------------------------------------------------------
# 1b. Encryption and Decryption functions (AES)
# ------------------------------------------------------

def encrypt_data(key, data):
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(data.encode(), AES.block_size))
    return iv, ciphertext

def decrypt_data(key, iv, ciphertext):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext.decode()

# ------------------------------------------------------
# 1c. Create Inverted Index and Encrypt It
# ------------------------------------------------------

def create_inverted_index(documents, key):
    # Step 1: Build plaintext index {word: [docIDs]}
    index = {}
    for doc_id, doc_text in documents.items():
        for word in doc_text.lower().split():
            word_hash = hashlib.sha256(word.encode()).hexdigest()  # hashed term
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)

    # Step 2: Encrypt the index using AES
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        iv, enc_word = encrypt_data(key, word_hash)
        encrypted_doc_ids = []
        for doc_id in doc_ids:
            iv2, enc_id = encrypt_data(key, doc_id)
            encrypted_doc_ids.append((iv2, enc_id))
        encrypted_index[(iv, enc_word)] = encrypted_doc_ids

    return encrypted_index

# ------------------------------------------------------
# 1d. Search Function
# ------------------------------------------------------

def search(encrypted_index, query, key):
    # Step 1: Hash query
    query_hash = hashlib.sha256(query.lower().encode()).hexdigest()

    # Step 2: Encrypt query
    iv_q, enc_query = encrypt_data(key, query_hash)

    # Step 3: Search in encrypted index
    results = []
    for (iv, enc_word), enc_doc_list in encrypted_index.items():
        # decrypt each index key to compare
        word = decrypt_data(key, iv, enc_word)
        if word == query_hash:
            # decrypt matching document IDs
            for iv2, enc_id in enc_doc_list:
                doc_id = decrypt_data(key, iv2, enc_id)
                results.append(doc_id)
    return results

# ------------------------------------------------------
# 1a. Create Dataset
# ------------------------------------------------------

documents = {
    "doc1": "cryptography enables secure communication and privacy",
    "doc2": "encryption provides confidentiality of data",
    "doc3": "searchable encryption allows search over encrypted data",
    "doc4": "symmetric encryption uses the same key for encryption and decryption",
    "doc5": "public key encryption uses a key pair",
    "doc6": "homomorphic encryption allows computation on encrypted data",
    "doc7": "paillier and rsa are examples of encryption schemes",
    "doc8": "machine learning models can use encrypted training data",
    "doc9": "secure data sharing is vital in distributed systems",
    "doc10": "searchable symmetric encryption combines indexing and encryption"
}

# Generate symmetric key (AES)
key = get_random_bytes(16)

# Build and encrypt index
encrypted_index = create_inverted_index(documents, key)

# Example Search
query = "encryption"
results = search(encrypted_index, query, key)

print(f"\n🔍 Search Query: '{query}'")
print("Matching Documents:", results)
