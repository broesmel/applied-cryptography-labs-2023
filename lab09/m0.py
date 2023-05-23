#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES 

"""
 M0: Dolev Yao Attacker
100
Diffie Hellman

Finally you get to immerse yourself in the role of the network adversary!

Unluckily for you, my protocol relies on an out of band verification on the derived keys!
nc aclabs.ethz.ch 50900


How can you make the keys end up on some known value?
"""

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

PORT = 50900

loco = 0

host = "aclabs.ethz.ch"
if loco:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def main():
    # r_a_init = snd_rcv({"command": "alice_initialisation"})
    # print(r_a_init)
    # a_pub = r_a_init["alice_key"]
    # a_hlo = {'resp': r_a_init["resp"], 'alice_key': a_pub}

    f_hlo = {'resp': "Hi Bob, I'm Alice. This is my public key", 'alice_key': 1}

    r_b_init = snd_rcv({"command": "bob_initialisation", 'alice_hello': f_hlo})
    print(r_b_init)
    b_pub = r_b_init["bob_key"]
    b_hlo = {'resp': r_b_init["resp"], 'bob_key': b_pub}

    r_a_init = snd_rcv({"command": "alice_initialisation"})
    print(r_a_init)
    a_pub = r_a_init["alice_key"]
    a_hlo = {'resp': r_a_init["resp"], 'alice_key': a_pub}

    e_hlo = {'resp': "Hi Alice, I'm Bob. This is my public key", 'bob_key': 1}


    r_a_fin = snd_rcv({"command": "alice_finished", 'bob_hello': e_hlo})
    print(r_a_fin)
    # => shared keys are both 1

    c = bytes.fromhex(r_a_fin["encrypted_flag"])
    nonce = bytes.fromhex(r_a_fin["nonce"])


    shared_bytes = int(1).to_bytes(int(1).bit_length(), 'big')
    secure_key = HKDF(master = shared_bytes, key_len = 32, salt = b'Secure alice and bob protocol', hashmod = SHA512, num_keys = 1)
    cipher = AES.new(secure_key, AES.MODE_CTR, nonce=nonce)
    # cipher.nonce = nonce

    print(cipher.decrypt(c))


if __name__ == "__main__":
    main()
