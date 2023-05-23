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
 M5: MD5 Authentication System
50
md5

    In our lab, we accidentally found a second pre-image for the MD5 hash value of our favorite food Pepper and lemon spaghetti with basil and pine nuts. We decided to build an authentication system based on our findings.

Read the server code, and try to login. Ask for the flag using the flag command!
nc aclabs.ethz.ch 50505 

"""    
tn = telnetlib.Telnet("aclabs.ethz.ch", 50505)

def main():
    r_token = snd_rcv({"command": "token"})
    print(r_token)
    nonce = bytes.fromhex(r_token['nonce'])
    token_enc = bytes.fromhex(r_token['token_enc'])

    known_collision = (
        bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2'), 
        bytes.fromhex('4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2')
    )

    for k in known_collision:
        print(MD5.new(k).hexdigest())

    m1 = b"Pepper and lemon spaghetti with basil and pine nuts"
    print(len(known_collision[0]), len(m1))
    recipe = b"Heat the oil in a large non-stick frying pan. Add the pepper and cook for 5 mins. Meanwhile, cook the pasta for 10-12 mins until tender. Add the courgette and garlic to the pepper and cook, stirring very frequently, for 10-15 mins until the courgette is really soft. Stir in the lemon zest and juice, basil and spaghetti (reserve some pasta water) and toss together, adding a little of the pasta water until nicely coated. Add the pine nuts, then spoon into bowls and serve topped with the parmesan, if using. Taken from [www.bbcgoodfood.com/recipes/pepper-lemon-spaghetti-basil-pine-nuts]"
    token = b"username:admin&m1:" + m1 + b"&fav_food_recipe:" + recipe

    ctxt_blocks = blockify(token_enc)
    ptxt_blocks = blockify(token)

    kstr_blocks = []

    for i in range(len(ctxt_blocks)):
        kstr_blocks += [xor(ctxt_blocks[i], ptxt_blocks[i])]
    print(kstr_blocks)
    kstr = b"".join(kstr_blocks)

    print(ctxt_blocks, len(ctxt_blocks))
    print(ptxt_blocks, len(ptxt_blocks))
    # we match from 'il in a large no', when we prepend 1 character to match message format
    # we need to remove what we prepend
    m1_inj = b'1:'+known_collision[0]+b'&fav_food_recipe:'
    m1_inj_blocks = blockify(m1_inj)
    ptxt_mod = ptxt_blocks[0] + m1_inj + b"".join(ptxt_blocks[len(m1_inj_blocks):])[3:]
    print(m1_inj_blocks)
    print(len(token),len(ptxt_mod))
    print(blockify(ptxt_mod))

    ctxt_mod = xor(kstr, ptxt_mod)

    r_login = snd_rcv({"command": "login", "nonce": nonce.hex(), "token_enc": ctxt_mod.hex(), "m2": known_collision[1].hex()})

    print(r_login)

    print(r_flag:=snd_rcv({"command": "flag"}))

    return

main()