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
These professors keep telling me that encrypt and mac is something I should avoid. Yet the proofs always involve very weirdly defined MAC schemes. To prove them wrong, I've used encrypt and mac to transmit my flag. I'm so confident in the correctness of this, that I'll even give you a partial decryption oracle.

Read the server code, and try to decrypt the encrypted flag. You can ask for the encrypted flag using the flag command!
nc aclabs.ethz.ch 50604 
"""

PORT = 50604

loco = 0

host = "aclabs.ethz.ch"
if loco:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)
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
    
    print(r:=snd_rcv({"command": "flag"})) 
    mac = bytes.fromhex(r['mac_tag'])
    ctxt = bytes.fromhex(r['ctxt'])
    nonce = bytes.fromhex(r['nonce'])
    print(ctxt, len(ctxt))

    print(r:=snd_rcv({"command": "encrypt", "ptxt": 'f'}))
    mac_0 = bytes.fromhex(r['mac_tag'])
    ctxt_0 = bytes.fromhex(r['enc_flag'])
    nonce_0 = bytes.fromhex(r['nonce'])
    print(r:=snd_rcv({"command": "decrypt", "ctxt": ctxt_0.hex(), "mac_tag": mac_0.hex(), "nonce": nonce_0.hex()}))
    print(r:=snd_rcv({"command": "decrypt", "ctxt": ctxt[0:1].hex(), "mac_tag": mac_0.hex(), "nonce": nonce.hex()}))

    single_letter_macs = dict()


    for x in range(128):
        # print(f"{x=}")
        r = snd_rcv({"command": "encrypt", "ptxt": chr(x)})
        mac_x = bytes.fromhex(r['mac_tag'])
        enc_x = bytes.fromhex(r['enc_flag'])
        nonce_x = bytes.fromhex(r['nonce'])
        single_letter_macs[x] = mac_x

    ptxt = ''
    for c in range(len(ctxt)):
        for x in range(128):
            r = snd_rcv({"command": "encrypt", "ptxt": ptxt+chr(x)})
            mac_x = bytes.fromhex(r['mac_tag'])
            r=snd_rcv({"command": "decrypt", "ctxt": ctxt[0:c+1].hex(), "mac_tag": mac_x.hex(), "nonce": nonce.hex()})
            if(r['success']):
                ptxt += chr(x)
                print(f"... decrypting: {ptxt=}", end='\r')
                break
    
    print('\n'+ptxt)

    return


if(__name__ == "__main__"):
    main()