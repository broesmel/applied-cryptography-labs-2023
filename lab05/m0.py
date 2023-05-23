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
import re

def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r

def blockify(a, blocksize=16):
    return [a[i : i + blocksize] for i in range(0, len(a), blocksize)]



tn = telnetlib.Telnet("aclabs.ethz.ch", 50406)


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
n this challenge you will be implementing Facebook's password onion.

# Salt is 20 bytes
def onion(pw, salt):
  h1 = md5(pw)
  h2 = HMAC[SHA1](h1, salt)
  h3 = HMAC[SHA256](h2, SECRET)
  # Use n = 2**10, r = 32, p = 2, key_len = 64
  h4 = scrypt(h3, salt)
  h5 = HMAC[SHA256](h4, salt)
  return h5

Notationally, the signature of HMAC is HMAC[ALG](msg, key) and that of scrypt is scrypt(pw, salt)

The flag is the digest obtained by applying the onion construction to the following parameters (all hex encoded)

PW = '6f6e696f6e732061726520736d656c6c79'
SECRET = '6275742061726520617765736f6d6520f09f988b'
SALT = '696e2061206e69636520736f6666726974746f21'
"""    

# Salt is 20 bytes
def onion(pw, salt, SECRET):
    h1 =  MD5.new(pw) # h1 = md5(pw)
    h2 = HMAC.new(salt, h1.digest(), SHA1) # h2 = HMAC[SHA1](h1, salt)
    h3 = HMAC.new(SECRET, h2.digest(), SHA256) # h3 = HMAC[SHA256](h2, SECRET)
    # Use n = 2**10, r = 32, p = 2, key_len = 64
    h4 =   scrypt(h3.digest(), salt, N = 2**10, r = 32, p = 2, key_len = 64) # h4 = scrypt(h3, salt
    h5 = HMAC.new(salt, h4, SHA256) # HMAC[SHA256](h4, salt)
    return h5

def main():

    PW = '6f6e696f6e732061726520736d656c6c79'
    SECRET = '6275742061726520617765736f6d6520f09f988b'
    SALT = '696e2061206e69636520736f6666726974746f21'

    pw = bytes.fromhex(PW)
    salt = bytes.fromhex(SALT)
    secret = bytes.fromhex(SECRET)
    o = onion(pw, salt, secret)
    print(o.digest().hex())

    return

main()