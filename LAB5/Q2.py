
# Server

import socket
import hashlib

HOST = '127.0.0.1'
PORT = 65432

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Server listening...")
    conn, addr = s.accept()
    with conn:
        print("Connected by", addr)
        data = conn.recv(1024)
        if not data:
            print("No data received")
        else:
            print("Received data:", data.decode())
            # Compute SHA-256 hash
            hash_value = hashlib.sha256(data).hexdigest()
            # Send hash back to client
            conn.sendall(hash_value.encode())
            print("Hash sent:", hash_value)

# Client 
            
import socket
import hashlib

HOST = '127.0.0.1'
PORT = 65432

message = "Hello, verify my data integrity!"

# Compute local hash
local_hash = hashlib.sha256(message.encode()).hexdigest()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(message.encode())           # Send message
    received_hash = s.recv(1024).decode() # Receive hash from server

print("Local hash:   ", local_hash)
print("Received hash:", received_hash)

if local_hash == received_hash:
    print("Integrity verified ✅")
else:
    print("Data corrupted or tampered ❌")

