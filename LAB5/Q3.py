import hashlib
import random
import string
import time

# -----------------------------
# Generate random dataset
# -----------------------------
def generate_random_strings(n=50, length_range=(5, 20)):
    dataset = []
    for _ in range(n):
        length = random.randint(*length_range)
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(s)
    return dataset

# -----------------------------
# Hashing function
# -----------------------------
def compute_hashes(dataset, algorithm='md5'):
    hashes = {}
    start_time = time.time()
    
    for s in dataset:
        if algorithm.lower() == 'md5':
            h = hashlib.md5(s.encode()).hexdigest()
        elif algorithm.lower() == 'sha1':
            h = hashlib.sha1(s.encode()).hexdigest()
        elif algorithm.lower() == 'sha256':
            h = hashlib.sha256(s.encode()).hexdigest()
        else:
            raise ValueError("Unsupported algorithm")
        hashes[s] = h
    
    elapsed_time = time.time() - start_time
    return hashes, elapsed_time

# -----------------------------
# Collision detection
# -----------------------------
def detect_collisions(hashes):
    seen = {}
    collisions = []
    for s, h in hashes.items():
        if h in seen:
            collisions.append((seen[h], s, h))  # (original, duplicate, hash)
        else:
            seen[h] = s
    return collisions

# -----------------------------
# Experiment
# -----------------------------
dataset = generate_random_strings(n=100, length_range=(5, 15))
for algo in ['md5', 'sha1', 'sha256']:
    hashes, elapsed = compute_hashes(dataset, algo)
    collisions = detect_collisions(hashes)
    print(f"\nAlgorithm: {algo.upper()}")
    print(f"Computation time: {elapsed:.6f} sec")
    print(f"Number of collisions: {len(collisions)}")
    if collisions:
        print("Collisions found:", collisions)
