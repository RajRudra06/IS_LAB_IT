# ==========================================================
# Lab Exercise 2: Public-Key Searchable Encryption (PKSE)
# using the Paillier Cryptosystem
# ==========================================================

import math, random
from Crypto.Util.number import getPrime, inverse
from hashlib import sha256

# ----------------------------------------------------------
# 2a. CREATE A DATASET  (ten text documents)
# ----------------------------------------------------------
documents = {
    "doc1": "machine learning enables computers to learn from data",
    "doc2": "encryption protects sensitive information from attackers",
    "doc3": "data privacy is a growing concern in modern systems",
    "doc4": "cryptography ensures secure communication between parties",
    "doc5": "searchable encryption allows queries on encrypted data",
    "doc6": "homomorphic encryption supports computation on ciphertexts",
    "doc7": "paillier cryptosystem provides additive homomorphism",
    "doc8": "public key cryptography uses key pairs for encryption",
    "doc9": "secure systems rely on mathematical hardness assumptions",
    "doc10": "data science integrates statistics and computing"
}

# ----------------------------------------------------------
# 2b. IMPLEMENT PAILLIER ENCRYPTION AND DECRYPTION
# ----------------------------------------------------------
def L(u, n):
    return (u - 1) // n

def generate_paillier_keypair(bit_length=512):
    p = getPrime(bit_length // 2)
    q = getPrime(bit_length // 2)
    n = p * q
    lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
    g = n + 1
    nsq = n * n
    mu = inverse(L(pow(g, lam, nsq), n), n)
    return (n, g), (lam, mu)

def paillier_encrypt(pub, m):
    n, g = pub
    nsq = n * n
    r = random.randrange(1, n)
    while math.gcd(r, n) != 1:
        r = random.randrange(1, n)
    return (pow(g, m, nsq) * pow(r, n, nsq)) % nsq

def paillier_decrypt(pub, priv, c):
    n, g = pub
    lam, mu = priv
    nsq = n * n
    u = pow(c, lam, nsq)
    return (L(u, n) * mu) % n

# ----------------------------------------------------------
# 2c. CREATE AN ENCRYPTED INVERTED INDEX
# ----------------------------------------------------------
def create_encrypted_index(documents, pub_key):
    index = {}
    # Step 1: build normal inverted index (word -> list of doc IDs)
    for doc_id, text in documents.items():
        for word in text.split():
            w = word.lower()
            word_hash = int.from_bytes(sha256(w.encode()).digest(), byteorder='big')
            if word_hash not in index:
                index[word_hash] = []
            index[word_hash].append(doc_id)

    # Step 2: encrypt the index using Paillier
    encrypted_index = {}
    for word_hash, doc_ids in index.items():
        enc_word = paillier_encrypt(pub_key, word_hash % pub_key[0])
        enc_doc_ids = [paillier_encrypt(pub_key, int(doc_id.strip("doc")) % pub_key[0])
                       for doc_id in doc_ids]
        encrypted_index[enc_word] = enc_doc_ids
    return encrypted_index

# ----------------------------------------------------------
# 2d. IMPLEMENT THE SEARCH FUNCTION
# ----------------------------------------------------------
def search_encrypted_index(encrypted_index, query, pub_key, priv_key):
    query_hash = int.from_bytes(sha256(query.lower().encode()).digest(), byteorder='big')
    enc_query = paillier_encrypt(pub_key, query_hash % pub_key[0])

    results = []
    for enc_word, enc_docs in encrypted_index.items():
        dec_word = paillier_decrypt(pub_key, priv_key, enc_word)
        if dec_word == (query_hash % pub_key[0]):
            for enc_doc_id in enc_docs:
                dec_doc = paillier_decrypt(pub_key, priv_key, enc_doc_id)
                results.append(f"doc{dec_doc}")
    return results

# ----------------------------------------------------------
# MAIN EXECUTION
# ----------------------------------------------------------
if __name__ == "__main__":
    # Generate keypair
    pub, priv = generate_paillier_keypair()

    # Build encrypted index
    enc_index = create_encrypted_index(documents, pub)
    print("Encrypted index created successfully.")

    # Run a search
    query = "encryption"
    results = search_encrypted_index(enc_index, query, pub, priv)

    print(f"\nSearch Query: {query}")
    print("Documents matching query:", results)
