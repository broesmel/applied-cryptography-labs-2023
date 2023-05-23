#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from string import ascii_letters, digits

from itertools import product

from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

"""
In this challenge, we are composing HMAC and AES in CBC mode into an Encrypt-and-Mac scheme.

A random message consisting of 4 bytes is encrypted using the composed scheme and the ciphertext is given to you.

We ensured that no padding oracles exist by not providing any decryption capabilities. Since we are very generous, we allow you to request for the authentication key, used in HMAC, with the command corrupt.

Your task is to correctly guess the random message 128 consecutive times.
nc aclabs.ethz.ch 50603 
"""

tn = telnetlib.Telnet("aclabs.ethz.ch", 50603)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r

def blockify(a, blocksize=16):
    return [a[i : i + blocksize] for i in range(0, len(a), blocksize)]

def snd_rcv(req):
    json_send(req)
    return json_recv()

def main():
    
    lt = dict()
    r=snd_rcv({"command": "corrupt",})
    print(r)
    k_auth = bytes.fromhex(r['res'].split(" ")[-1])

    for p in product(ascii_letters + digits, repeat=4):
        ptxt = "".join(p)
        tag2_hex = HMAC.new(k_auth, ptxt.encode(), SHA256).hexdigest()
        print(f"computing {ptxt=}, {tag2_hex[:8]}", end='\r')
        lt[tag2_hex] = ptxt


    for i in range(128):
        r=snd_rcv({"command": "challenge",})
        print(r)
        challenge = bytes.fromhex(r['res'])
        
        print(f"{challenge.hex()=}, {k_auth.hex()=}")

        key_len = 16
        message_len = 4
        tag_len = 32
        iv = challenge[:key_len]
        ciphertext = challenge[key_len:-tag_len]
        tag = challenge[-tag_len:]
        tag_hex = tag.hex()

        print(f"{iv.hex()=}, {ciphertext.hex()=}, {tag.hex()=}")

        ptxt = lt[tag_hex]

        print(f"{ptxt}")

        r = snd_rcv({"command": "guess", "guess": ptxt})

        print(r)



    print(r:=snd_rcv({"command": "flag"}))


if(__name__ == "__main__"):
    main()