alpha="ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ct = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"

def decrypt_with(a_inv,b):
    res=[]
    for ch in ct:
        y = alpha.index(ch)
        x = (a_inv * ((y - b) % 26)) % 26
        res.append(alpha[x])
    return "".join(res)

# brute-force: try all a coprime with 26 and all b
candidates=[]
for a in range(1,26):
    from math import gcd
    if gcd(a,26)!=1: 
        continue
    # compute multiplicative inverse of a mod26
    for ai in range(1,26):
        if (a*ai)%26==1:
            a_inv=ai
            break
    for b in range(26):
        pt = decrypt_with(a_inv,b)
        # check known plaintext "ab" -> "GL" constraint:
        # encryption E(0)=b -> should be 'G' (index 6)
        # encryption E(1)=a+b -> should be 'L' (index 11)
        if (b %26)==6 and ((a+b)%26)==11:
            print("Found a,b:",a,b,"=>",pt)
