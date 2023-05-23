#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad


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
    # ECB mode encryption: simple XOR of the plaintext with the key
    # 2 keys: left and right, generated using 2 random bytes and then hashed with SHA256
    print(r:=snd_rcv({"command": "query", "m": bytes([0]*16).hex()}))
    print(r:=snd_rcv({"command": "query", "m": bytes([1]*16).hex()}))
    
    return 
    for i in range(64):
        print(r:=snd_rcv({"command": "query", "m": bytes([0]*16).hex()}))
        print(r:=snd_rcv({"command": "guess", "b": 1}))

    print(r:=snd_rcv({"command": "flag"}))