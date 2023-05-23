#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256, HMAC
from Crypto.Cipher import AES

import secrets


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
    IND-CCA is all I'll ever need.

Now that you have successfully implemented a secure AEAD scheme, reflect on what the security guarantees AEAD actually provides.

Take a look at the server code: you never learn the secret key, and, by the definition IND-CCA security, you will never be able to forge new valid tokens... Or will you?
nc aclabs.ethz.ch 50707 

"""
PORT = 50707
loco = 0

host = "aclabs.ethz.ch"
if loco:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def main():
    r_token = snd_rcv({"command": "get_token"})
    print(r_token)
    token_0 = bytes.fromhex(r_token['guest token'])
    token_0_iv = token_0[:16]
    token_0_enc = token_0[16:-24]
    token_0_tag = token_0[-24:]

    token_pt = pad(b'guest', 16)

    r_auth = snd_rcv({"command": "authenticate", "token": token_0.hex()})
    print(f"{r_auth=}")

    r_state = snd_rcv({"command": "show_state", "prefix": b'uh '.hex()})
    print(r_state)

    key_mod = bytes([0]*31 + [0] + [0]*23 + [1])
    r_rekey = snd_rcv({"command": "rekey", "key": key_mod.hex()})
    print(f"{r_rekey=}")

    r_token = snd_rcv({"command": "get_token"})
    print(r_token)
    token_1 = bytes.fromhex(r_token['guest token'])
    token_1_iv = token_1[:16]
    token_1_enc = token_1[16:-24]
    token_1_tag = token_1[-24:]

    r_auth = snd_rcv({"command": "authenticate", "token": token_1.hex()})
    print(f"{r_auth=}")

    i = 0
    while i<2**(32*8):
        i += 1
        keymod = i.to_bytes(32, 'big')+ bytes([0]*24)
        r_rekey = snd_rcv({"command": "rekey", "key": keymod.hex()})
        print(f"{r_rekey=}")
        r_auth = snd_rcv({"command": "authenticate", "token": token_1.hex()})
        print(f"{r_auth=}")
        if not 'error' in r_auth:
            print(key_mod)
            r_state = snd_rcv({"command": "show_state", "prefix": b'uh '.hex()})
            print(r_state)
            if(r_state['resp'] != 'uh ' + "What a beautiful dream, That could flash on the screen"):
                break

    return

    for x in range(0xff):
        # key_mod = bytes([0]*31 + [0] + [0]*23 + [x+1])
        # r_rekey = snd_rcv({"command": "rekey", "key": key_mod.hex()})
        # print(r_rekey)
        
        r_token2 = snd_rcv({"command": "get_token"})
        print(r_token2)
        token2_guest = bytes.fromhex(r_token2['guest token'])
        iv2 = token2_guest[:16]
        token2_enc = token2_guest[16:-24]
        token2_tag = token2_guest[-24:]

        print(token_tag, token2_tag)

        r_auth = snd_rcv({"command": "authenticate", "token": (xor(iv, bytes([1] + [0]*15))+token_enc).hex()})
        print(r_auth)
        if not 'error' in r_auth:
            r_state = snd_rcv({"command": "show_state", "prefix": b'uh '.hex()})
            print(x, r_state)

            break


    return

main()