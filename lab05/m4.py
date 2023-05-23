#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, MD5, HMAC, SHA1
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt

import hmac

import secrets

from string import ascii_letters, digits
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
 M4: Time Waits for No One
50
warmup

    Oh, look at you, you can bruteforce! Let's see how fast you are.

You now have to guess on-time the password 5 consecutive times. Then, you can ask for the flag using the flag command.
nc aclabs.ethz.ch 50504 

"""    
tn = telnetlib.Telnet("aclabs.ethz.ch", 50504)

def main():

    pws = itertools.product('abcdefghijklmnopqrstuvwxyz', repeat=5)

    hash_table = dict()
    r_salt = snd_rcv({"command": "salt"})['salt']
    print(r_salt)
    salt = bytes.fromhex(r_salt)
    for x in pws:
        pw = "".join(x)
        # poth = hmac.new(key=salt, msg=pw.encode(), digestmod=SHA256).digest()
        poth = HMAC.new(key=salt, msg=pw.encode(), digestmod=SHA256).digest()
        print(f"----==== computing {pw}... ====----", end="\r")
        hash_table[poth] = pw

    for i in range(5):
        hash = bytes.fromhex(snd_rcv({"command": "password"})['pw_hash'])
        print(f"{i:02d} - {hash} - {salt}")

        if hash in hash_table:
            pw = hash_table[hash]
            print(pw)

        
        r = snd_rcv({"command": "guess", "password": pw})
        print(r)
    
    print(snd_rcv({"command": "flag"}))
    return

main()