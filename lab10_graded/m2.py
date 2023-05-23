#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json

# to generate q
from Crypto.Util.number import getPrime, getRandomNBitInteger

# Copied from the server
import secrets
from Crypto.Cipher import AES

from Crypto.Hash import SHA256

from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import isPrime

"""
 M2: Problematic Public Parameters
200
graded interactive

    They say "trust, but verify". Feel free to choose g and p, but I will keep an eye on you...

The server implements a DHIES "flag oracle" for a user Bob:

    The set_params command sets the DHIES parameters p and g for the server to some values of your choosing. The server runs some sanity checks on the provided values. The server then samples Bob's keypair and returns the public key to you. This command may only be called once.
    The encrypt command returns the flag, DHIES-encrypted under Bob's public key. You must set the parameters before calling this command. This command may only be called once.

Recover the flag!
nc aclabs.ethz.ch 51002 
"""

# helper functions accumulated across the previous labs
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

# connection details
PORT = 51002
loco = 0
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)
    

def main():
    # info form the lecture 

    # The discrete logarithm setting
    # • Assume p and q are large primes and q divides p-1.
    # • So we can write p = kq + 1 for some integer k; so k = (p-1)/q.
    # • (So p and q do not have the same flavour as in RSA!).
    # • Often, but not always, k=2.
    # then picking a random int h mod p gives us a generator g 
    # g = h^(p-1)/q mod p 
    # g = h^k mod p

    # • Fact 1: if g ≠ 1 mod p, then the q powers of g, namely Gq =
    # {g,g2,g3,...g q} are all distinct mod p.
    # • Fact 2: gq = 1 mod p.
    # • Fact 3: if we multiply together two elements in the set Gq, we
    # obtain a third element that is also in the set Gq.
    # • In combination, these facts mean that the set Gq forms a group of
    # order q; the group operation is multiplication mod p.
    # • Gq is a cyclic group (everything is a power of g).
    # • We say that g is a generator of Gq.
    # • The number of elements in Gq is q, a prime.
    # Gq is a subgroup of the multiplicative group of integers mod p!!
    # if we can get a small q then we can solve the discrete log problem in Gq
    # if q is small enough we can even bruteforce this

    # Our requirements:
    # |p| >= 1024 bits
    # g %= p not in {0, 1, p-1}

    # we can choose q and then compute p to ensure that our g is a gen for both 
    # Gq and Gp
    q = getPrime(7) # 7 bit prime
    print(f"{q=}")
    k = 0
    p = 0
    h = 0
    g = 0
    while (not isPrime(p)): # ensure p is prime
        k = getRandomNBitInteger(1024) # ensure p is at least 1024 bits
        p = k*q + 1
    while(g in [0, 1, p-1]): # ensure g is not in {0, 1, p-1}
        h = secrets.randbelow(p)
        g = pow(h, k, p)

    print(f"{q=} {p.bit_length()=}, {g=}")
    
    r_params = snd_rcv({"command": "set_params", "g": g, "p": p})
    print(r_params)
    pk_other = int(r_params["bob_pubkey"])


    r_enc = snd_rcv({"command": "encrypt"})
    print(r_enc)

    pk = int(r_enc["pk"])
    c = bytes.fromhex(r_enc["ciphertext"])
    tag = bytes.fromhex(r_enc["tag"])
    nonce = bytes.fromhex(r_enc["nonce"])

    # we can compute the secret key sk by bruteforcing the discrete log problem
    # in our small group Gq of order q
    sk = 0
    for x in range(q):
        if pow(g, x, p) == pk:
            print(f"{x=}")
            sk = x
            break
    print(f"{sk=}")
    
    # now we can compute the shared Diffie-Hellman value, the secret bytes
    # and the symmetric key!
    # from the server:
    pk_bytes = pk.to_bytes(512, "big")

    # Compute shared Diffie-Hellman value
    shared = pow(pk_other, sk, p)
    shared_bytes = shared.to_bytes(512, "big")

    pk_other_bytes = pk_other.to_bytes(512, "big")
    K: bytes = HKDF(shared_bytes + pk_bytes + pk_other_bytes, 32, salt=b"", num_keys=1, context=b"dhies-enc", hashmod=SHA256) #type: ignore
    cipher = AES.new(K, AES.MODE_GCM, nonce=nonce)
    
    
    
    flag = cipher.decrypt_and_verify(c, tag)
    print(flag)


if __name__ == "__main__":
    main()
