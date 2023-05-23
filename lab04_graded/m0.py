#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

from secrets import randbits


def xor(X: bytes, Y: bytes):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50400)

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



def main():
    # from the server code:
    # ECB mode encryption: same pt will encrypt to the same ct
    # 2 keys: left and right, generated using 2 random bytes and then hashed with SHA256
    m0 = bytes([0]*16)
    # print(r0:=snd_rcv({"command": "query", "m": m0.hex()}))
    # print(r1:=snd_rcv({"command": "query", "m": m1.hex()}))


    # precompute all possible left ciphertexts of m0, and the corresponding ciphers
    # idea: meet in the middle, we can decrypt the doubly encrypted ciphertexts of m0 using a key based on 2 bytes, 
    # and then check if the decrypted ciphertexts are in the lookup table of precomputed ciphertexts
    lctxts = dict()
    # make sure that the lookup is fast !!! i.e. dict and not list
    ciphers = []
    # ciphers precomputed because i don't know if this takes long
    for lkey_src in range(0x10000):
        lkey = SHA256.new(lkey_src.to_bytes(2, 'big')).digest()
        lcipher = AES.new(lkey, AES.MODE_ECB)

        lctxt = lcipher.encrypt(m0)
        lctxts[lctxt] = [lkey_src]
        ciphers.append(lcipher)

    for i in range(64):
        found = False
        # get a doubly encrypted ciphertext of m0
        print(r0:=snd_rcv({"command": "query", "m": m0.hex()}), end='\r')
        ctxt = bytes.fromhex(r0["res"])


        # attempt decryption under all possible keys, if we precomputed this value, likely an encryption of m0 and not random
        # because 2 bytes were used for both keys, and hashing is deterministic, the keys match up
        for cipher in ciphers:
            rctxt = cipher.decrypt(ctxt)
            if(rctxt in lctxts):
                print(r:=snd_rcv({"command": "guess", "b": '0'}), 'b=0 ')
                found = True
                break
        
        if(not found):
            print(r:=snd_rcv({"command": "guess", "b": '1'}), 'b=1')
    
    print(r:=snd_rcv({"command": "flag"}))
    return

main()