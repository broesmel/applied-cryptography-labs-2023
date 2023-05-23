#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse


"""
 M5: Public Exponent
100
RSA

I trust my RSA so much that I'm going to make you change the public exponent as well! After all, public means that everyone should be able to do what they wish, right?
nc aclabs.ethz.ch 50805 

What happens if you give coprime exponents? What's their GCD?

Euclid's your buddy here
"""

def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r
def blockify(a, blocksize=16):
    return [a[i : i + blocksize] for i in range(0, len(a), blocksize)]


def readline():
    return tn.read_until(b"\n")
def json_recv():
    line = readline()
    return json.loads(line.decode())
def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def snd_rcv(req):
    json_send(req)
    return json_recv()

tn = telnetlib.Telnet("aclabs.ethz.ch", 50805)


# function for extended Euclidean Algorithm
def gcdExtended(a, b):
    # Base Case
    if a == 0 :
        return b,0,1
             
    gcd,x1,y1 = gcdExtended(b%a, a)
     
    # Update x and y using results of recursive
    # call
    x = y1 - (b//a) * x1
    y = x1
     
    return gcd,x,y

def main():
    
    N = int(snd_rcv({"command": "pub_key"})['N'], 16)
    
    
    # e1 = 11
    # e2 = 13
    # e1x+e2y=GCD(e1,e2)=1
    # c1**x * c2**y=m**(e1*x) * m**(e2*y) = m**(e1*x+e2*y) = m mod N

    # flag_enc_11 == pow(flag, 11, N)
    # flag_enc_13 == pow(flag, 13, N)
    # e1 = 11
    # e2 = 13
    # e1*x + e2*y = 1
    # x = (1 - e2*y) / e1
    # x = (1 - e2*y) * inverse(e1, N)
    
    
    e1 = 29
    e2 = 37
    flag_enc_1 = int(snd_rcv({"command": "encrypt", "e": e1})['ciphertext'], 16)
    flag_enc_2 = int(snd_rcv({"command": "encrypt", "e": e2})['ciphertext'], 16)
    c1 = flag_enc_1
    c2 = flag_enc_2
    
    _, x, y = gcdExtended(e1, e2)
    
    print(f"{(e1*x + e2*y) % N=}")



    m = ( pow(c1, x, N) * pow(c2, y, N) ) % N
    print(f"{long_to_bytes(m)=}")


    # flag = iroot(bytes_to_long(flag_enc), e)[0]     
    # print(long_to_bytes(flag))


if __name__ == "__main__":
    main()
