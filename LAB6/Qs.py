# # elgmal

# import random
# from hashlib import sha256

# # Small parameters for demo; use large primes in practice
# p, g = 467, 2

# # Key generation
# x = random.randint(1, p-2)  # private
# y = pow(g, x, p)            # public

# # Message
# m = "AliceDocument"
# h = int(sha256(m.encode()).hexdigest(),16) % p

# # Signing
# while True:
#     k = random.randint(1, p-2)
#     if pow(k,1,p-1) != 0:
#         break
# r = pow(g, k, p)
# k_inv = pow(k, -1, p-1)
# s = (k_inv*(h - x*r)) % (p-1)
# sig = (r,s)

# # Verification
# v1 = (pow(y,r,p) * pow(r,s,p)) % p
# v2 = pow(g,h,p)
# print("ElGamal signature valid:", v1==v2)


# # DH key exchange
# p, g = 467, 2
# a, b = random.randint(1,p-2), random.randint(1,p-2)
# A, B = pow(g,a,p), pow(g,b,p)       # public keys
# K_a = pow(B,a,p)                     # shared secret
# K_b = pow(A,b,p)
# print("Shared secret equal:", K_a==K_b)

# # Use shared secret to create simple MAC (hash)
# msg = "HelloBob"
# mac = sha256((msg + str(K_a)).encode()).hexdigest()
# # Verification at Bob side
# mac_b = sha256((msg + str(K_b)).encode()).hexdigest()
# print("MAC valid:", mac==mac_b)


# # Alice = client, Bob = server
# # Keys for Alice
# x_a = random.randint(1,p-2); y_a = pow(g,x_a,p)
# # Keys for Bob
# x_b = random.randint(1,p-2); y_b = pow(g,x_b,p)

# # Alice signs message
# msg = "ClientData"
# h = int(sha256(msg.encode()).hexdigest(),16) % p
# k = random.randint(1,p-2)
# r = pow(g,k,p)
# s = (pow(k,-1,p-1)*(h - x_a*r)) % (p-1)
# sig = (r,s)

# # Bob verifies using Alice's public key
# v1 = (pow(y_a,r,p) * pow(r,s,p)) % p
# v2 = pow(g,h,p)
# print("Client->Server signature valid:", v1==v2)

# # Server signs reply
# reply = "ServerAck"
# h2 = int(sha256(reply.encode()).hexdigest(),16) % p
# k2 = random.randint(1,p-2)
# r2 = pow(g,k2,p)
# s2 = (pow(k2,-1,p-1)*(h2 - x_b*r2)) % (p-1)
# sig2 = (r2,s2)

# # Alice verifies server reply
# v1b = (pow(y_b,r2,p) * pow(r2,s2,p)) % p
# v2b = pow(g,h2,p)
# print("Server->Client signature valid:", v1b==v2b)

import random
from hashlib import sha256
from math import gcd

# Small parameters for demo; use large primes in practice
p, g = 467, 2

# Key generation
x = random.randint(1, p-2)  # private
y = pow(g, x, p)            # public

# Message
m = "AliceDocument"
h = int(sha256(m.encode()).hexdigest(),16) % p

# Signing
while True:
    k = random.randint(1, p-2)
    if gcd(k, p-1) == 1:    # ensure invertible
        break
r = pow(g, k, p)
k_inv = pow(k, -1, p-1)
s = (k_inv*(h - x*r)) % (p-1)
sig = (r,s)

# Verification
v1 = (pow(y,r,p) * pow(r,s,p)) % p
v2 = pow(g,h,p)
print("ElGamal signature valid:", v1 == v2)


# DH key exchange
a, b = random.randint(1,p-2), random.randint(1,p-2)
A, B = pow(g,a,p), pow(g,b,p)
K_a, K_b = pow(B,a,p), pow(A,b,p)
print("Shared secret equal:", K_a == K_b)

# MAC check
msg = "HelloBob"
mac = sha256((msg + str(K_a)).encode()).hexdigest()
mac_b = sha256((msg + str(K_b)).encode()).hexdigest()
print("MAC valid:", mac == mac_b)


# Alice = client, Bob = server
x_a = random.randint(1,p-2); y_a = pow(g,x_a,p)
x_b = random.randint(1,p-2); y_b = pow(g,x_b,p)

# Alice signs message
msg = "ClientData"
h = int(sha256(msg.encode()).hexdigest(),16) % p
while True:
    k = random.randint(1, p-2)
    if gcd(k, p-1) == 1:
        break
r = pow(g, k, p)
s = (pow(k, -1, p-1) * (h - x_a*r)) % (p-1)
sig = (r,s)

v1 = (pow(y_a, r, p) * pow(r, s, p)) % p
v2 = pow(g, h, p)
print("Client->Server signature valid:", v1 == v2)

# Server signs reply
reply = "ServerAck"
h2 = int(sha256(reply.encode()).hexdigest(),16) % p
while True:
    k2 = random.randint(1, p-2)
    if gcd(k2, p-1) == 1:
        break
r2 = pow(g, k2, p)
s2 = (pow(k2, -1, p-1) * (h2 - x_b*r2)) % (p-1)
sig2 = (r2,s2)

v1b = (pow(y_b, r2, p) * pow(r2, s2, p)) % p
v2b = pow(g, h2, p)
print("Server->Client signature valid:", v1b == v2b)
