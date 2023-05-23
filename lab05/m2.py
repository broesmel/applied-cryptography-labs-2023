#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, MD5, HMAC, SHA1
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

from passlib.hash import argon2

import secrets

from string import ascii_letters, digits
from datetime import datetime, timezone
import re

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

"""
 M2: Rocking is good while you are young
100
warmup

Break (as in, find a preimage of) the following MD5 hash

b77fccfabb93aaf4eae345484c6d929b


"""    
tn = telnetlib.Telnet("aclabs.ethz.ch", 50501)

def main():
    data = open('rockyou.txt', encoding='latin-1').readlines()
    # data = re.findall('\w+', open('rockyou.txt', encoding='latin-1').read().lower())
    

    for d in data:
        d = d.strip()
        d_hash = MD5.new(d.encode()).hexdigest()
        print(f"----==== trying {d:32} - {d_hash} ====----", end="\r")
        g_hash = "9fb7009f8a9b4bc598b4c92c91f43a2c"
        if d_hash == g_hash:
            print(f"----==== FOUND IT! ====----")
            print(d)
            break


    return

main()