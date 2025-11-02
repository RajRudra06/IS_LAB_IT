import string

def generate_matrix(key):
    key = "".join(dict.fromkeys(key.upper().replace("J","I")+string.ascii_uppercase))
    matrix = [list(key[i:i+5]) for i in range(0,25,5)]
    return matrix

def playfair_encrypt(text, matrix):
    text = text.upper().replace("J","I").replace(" ", "")
    if len(text)%2!=0: text+="X"
    result=""
    for i in range(0,len(text),2):
        a,b=text[i],text[i+1]
        ax,ay,bx,by=-1,-1,-1,-1
        for r in range(5):
            if a in matrix[r]: ax,ay=r,matrix[r].index(a)
            if b in matrix[r]: bx,by=r,matrix[r].index(b)
        if ax==bx: # same row
            result+=matrix[ax][(ay+1)%5]+matrix[bx][(by+1)%5]
        elif ay==by: # same column
            result+=matrix[(ax+1)%5][ay]+matrix[(bx+1)%5][by]
        else: # rectangle
            result+=matrix[ax][by]+matrix[bx][ay]
    return result

matrix=generate_matrix("GUIDANCE")
msg="The key is hidden under the door pad"
print("Encrypted:", playfair_encrypt(msg, matrix))
