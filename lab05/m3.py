#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, MD5, HMAC, SHA1
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

import secrets

from string import ascii_letters, digits
from datetime import datetime, timezone
import itertools

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
 M3: Salty
100

We retrieved this hashed password from a database. We know that HMAC-SHA1 was used and that the password is exactly 6 characters long. We also know that all characters are lowercase letters ([a-z]).

The HMAC is computed by using the password as a key and the salt as the message.

SALT = b49d3002f2a089b371c3
HASH = d262db83f67a37ff672cf5e1d0dfabc696e805bc

How fast can you retrieve the password? Enter the password here (UTF-8 string format):



"""    
tn = telnetlib.Telnet("aclabs.ethz.ch", 50501)
hash = "d262db83f67a37ff672cf5e1d0dfabc696e805bc"

def create_hashtable() -> dict:
    hashtable = dict()
    pws = itertools.product('abcdefghijklmnopqrstuvwxyz', repeat=6)
    salt = bytes.fromhex("b49d3002f2a089b371c3")

    # ohnomy
    # with open("hashtable_sha1_6lowercase_salted_b49d3002f2a089b371c3.txt", "w") as f:
    for x in pws:
        pw = "".join(x)
        poth = HMAC.new(key=pw.encode(), msg=salt, digestmod=SHA1).hexdigest()
        hashtable[poth] = pw
        # f.write(poth + ' ' + pw + '\n')
        print(f"{pw} - {poth} - {hash}")

        if poth == hash:
            print("Found it!")
            print(pw)
            break

    return hashtable

def main():
    ht = create_hashtable()
    print(ht[hash])

    # hashcat -m 60 -a 3 -1 l -O 6 --hex-salt 

main()