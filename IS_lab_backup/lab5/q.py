# Lab 5: Hashing
# Requirements: (standard Python) pip install pycryptodome if you plan to use AES in network demos
# Exercises:
# 1) Implement user-defined hash function starting with initial value 5381 (DJB-like) and keep within 32-bit.
# 2) Using socket programming, demonstrate data-integrity verification: server computes hash and returns to client.
# 3) Performance analysis: MD5, SHA-1, SHA-256 on 50-100 random strings and collision detection.

# Q1) Custom hash function
def custom_hash(s):
    h = 5381
    for ch in s:
        h = ((h * 33) + ord(ch)) & 0xFFFFFFFF  # keep 32-bit
        # optional bit mixing:
        h = h ^ ((h << 7) & 0xFFFFFFFF)
    return h

print("# Q1 custom hash:", hex(custom_hash("Information Security")))

# Q2) Socket programming demo
# Save this file and run server and client in separate processes or terminals
# server_hash.py (run first):
"""
import socket, hashlib
s = socket.socket()
s.bind(('localhost', 9999))
s.listen(1)
print('Server listening on localhost:9999')
conn, addr = s.accept()
print('Connected by', addr)
data = b''
while True:
    chunk = conn.recv(4096)
    if not chunk: break
    data += chunk
# compute hash and send
h = hashlib.sha256(data).hexdigest().encode()
conn.send(h)
conn.close()
s.close()
"""

# client_hash.py (run after server):
"""
import socket, hashlib
msg = b'This is a test message to verify integrity.'
s = socket.socket()
s.connect(('localhost', 9999))
s.sendall(msg)
h_recv = s.recv(1024).decode()
h_local = hashlib.sha256(msg).hexdigest()
print('Server hash:', h_recv)
print('Local  hash :', h_local)
print('Integrity OK' if h_recv == h_local else 'Tampered')
s.close()
"""

# Q3) Performance analysis of MD5, SHA-1, SHA-256
import hashlib, random, string, time
def random_strings(n, length=100):
    return [''.join(random.choices(string.ascii_letters + string.digits, k=length)) for _ in range(n)]

data = random_strings(60, length=200)  # 60 strings
algos = {"MD5": hashlib.md5, "SHA1": hashlib.sha1, "SHA256": hashlib.sha256}
results = {}
for name, fn in algos.items():
    t0 = time.time()
    hashes = [fn(s.encode()).hexdigest() for s in data]
    t1 = time.time()
    coll = len(hashes) != len(set(hashes))
    results[name] = {"time": t1-t0, "collisions": coll}
for name, info in results.items():
    print(f"# Q3 {name}: time={info['time']:.6f}s, collisions={info['collisions']}")

# Additional exercise: client sends parts; server reassembles and replies hash — that is implemented in server/client structure above by reading chunks.
