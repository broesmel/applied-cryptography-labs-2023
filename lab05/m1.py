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
 M1: Noble Gases Do Not Like to Mix
100
warmup

In this challenge you will be implementing a password hashing method that is much better than Facebook's

unz

To use argon2, you might want to look at the passlib library

Interact with the server to extract the flag for this challenge.
nc aclabs.ethz.ch 50501
"""    
tn = telnetlib.Telnet("aclabs.ethz.ch", 50501)

def main():

    # Get the password
    pw = bytes.fromhex(snd_rcv({"command": "password"})["res"])
    
    h = argon2.hash(pw)
    
    g = snd_rcv({"command": "guess", "guess": h})

    print(g)

    return

main()