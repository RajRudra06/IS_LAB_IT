import numpy as np

def hill_encrypt(text, key):
    text = text.lower().replace(" ", "")
    if len(text)%2!=0: text+="x"
    result=""
    for i in range(0,len(text),2):
        vec=np.array([[ord(text[i])-97],[ord(text[i+1])-97]])
        res=(np.dot(key,vec)%26).flatten()
        result+="".join([chr(int(x)+97) for x in res])
    return result

key = np.array([[3,3],[2,7]])
msg="Weliveinaninsecureworld"
print("Encrypted:", hill_encrypt(msg, key))
