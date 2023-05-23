#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json

# from the server
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes, getRandomInteger

from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA512

import secrets

"""
 M0: Forward Secrecy
100
ElGamal Authenticated Key Exchange

    I have an extremely important message I need to send to my boss!

    I know the person controlling the network might try to impersonate my boss. But by performing an authenticated key exchange and only then sending my secret I can protect against this. Furthermore, my novel scanner technology can tell me if my boss has been compromised, so I can make sure to not share the secret with them in that case.

nc aclabs.ethz.ch 51200 
"""

# helper functions accumulated across the previous labs
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

# connection details
PORT = 51200
loco = 0
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)
    

# from the server code
# Secure Diffie Hellamn parameters. Large prime p and a generator g of the group.
p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
q = (p - 1) // 2
g = 3

def main():

    r_client_hello = snd_rcv({"command": "client_hello"})
    print(r_client_hello)
    client_nonce = bytes.fromhex(r_client_hello["client_nonce"])


    # generate a random private key
    client_private = secrets.randbelow(q - 1) + 1
    # compute the public key
    client_public = pow(g, client_private, p)

    r_boss_hello = snd_rcv({"command": "boss_hello", "pubkey": client_public, "client_nonce": client_nonce.hex()})
    print(r_boss_hello)
    boss_nonce = bytes.fromhex(r_boss_hello["boss_nonce"])
    boss_public = r_boss_hello["pubkey"]
    # send the public key to the server
    r_client_finished = snd_rcv({"command": "client_finished", "boss_nonce": boss_nonce.hex(), "pubkey": boss_public})
    print(r_client_finished)
    # shared_secret = secrets.randbelow(p)
    # eph_private = secrets.randbelow(q - 1) + 1
    # eph_public = pow(g, eph_private, p)
    c_1 = r_client_finished["encrypted_shared_key"]["c1"] # pow(g, eph_private, p)
    c_2 = r_client_finished["encrypted_shared_key"]["c2"] # (eph_public * shared_secret) % p
    ciphertext = bytes.fromhex(r_client_finished["ciphertext"])

    finished_nonce = bytes.fromhex(r_client_finished["nonce"])


    r_compromise = snd_rcv({"command": "compromise"})
    print(r_compromise)
    boss_private = r_compromise["secret"]

    K = pow(c_1, boss_private, p)
    shared_secret = (c_2 * pow(K, -1, p)) % p
    secure_key = HKDF(
        master=long_to_bytes(shared_secret),
        key_len=32,
        salt=client_nonce + boss_nonce,
        hashmod=SHA512,
        num_keys=1,
    )

    cipher = AES.new(
        secure_key, AES.MODE_CTR, nonce=finished_nonce
    )
    message = cipher.decrypt(ciphertext)   



    print(message)

if __name__ == "__main__":
    main()
