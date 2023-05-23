#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json

# Copied from the server
import math
from typing import Tuple
from Crypto.Hash import MD5, HMAC, SHA256


"""
 M1: Magic Mersenne MAC
200
graded interactive

    Counter? Wegman-Carter? I barely know her! Besides, I've haven't even finished reading the chapter on AE security...

The server implements an AE encryption and decryption oracle. The encryption oracle uses a composition of AES (in counter mode) and a Carter-Wegman MAC (in an encrypt-then-MAC fashion) to encrypt messages of your choice. The messages must be exactly 15 bytes long.

The corresponding decryption oracle verifies the tag and decrypts the message. Your objective is to forge a valid ciphertext for the message "Give me a flag!".

    The encrypt command encrypts a message of your choice using the scheme described above.
    The decrypt command decrypts a ciphertext. If decryption succeeds and yields the plaintext "Give me a flag!", you receive the flag. The plaintext is never returned to you and is simply discarded.

nc aclabs.ethz.ch 51001 
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
PORT = 51001
loco = 0
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)
    

def main():
    # AES-CTR creates a keystream, to which the plaintext is XORed
    # and we can supply the nonce with which the counter is initialized
    m1 = "Give me a flag0"
    m2 = "00000000000000!"
    nonce = bytes([0] * 8).hex()
    r_c1 = snd_rcv({"command": "encrypt", "message": m1, "nonce": nonce})
    print(r_c1)
    r_c2 = snd_rcv({"command": "encrypt", "message": m2, "nonce": nonce})
    print(r_c2)
    tag1 = int(r_c1['tag'], 16)
    tag2 = int(r_c2['tag'], 16)
    c1 = bytes.fromhex(r_c1['ciphertext'])
    c2 = bytes.fromhex(r_c2['ciphertext'])
    c = c1[:-1] + c2[-1:]
    print(c, len(c))
    # so now we have the encryption of the message we need. We now need
    # to forge a tag for this encryption. 
    # len(message) is 15
    # we know p from the server:
    p = 2**127-1
    # thus we can recompute:
    # tag1 - tag2 = h1 - h2 % p
    # h1-h2 = (K**3  + c1 * K**2 + 15 * K) % p - (K**3  + c2 * K**2 + 15 * K) % p
    # h1-h2 = (c1-c2) * K**2 % p
    # K**2 = (h1-h2) * (c1-c2)**-1 % p
    c1_int = int.from_bytes(c1, 'big') % p
    c2_int = int.from_bytes(c2, 'big') % p

    K_sqr = (tag1 - tag2) * pow(c1_int-c2_int, -1, p) % p
    print(K_sqr) # matches the servers K**2

    # now we can ask the server to encrypt a message with c = c+diff:
    msg_c_plus = "Give me a flag"+chr(ord('!')+1) # try to make diff small
    r_c_plus = snd_rcv({"command": "encrypt", "message": msg_c_plus, "nonce": nonce})
    diff = int(r_c_plus['ciphertext'], 16) - int.from_bytes(c, 'big')
    print(f"{diff=}")
    tag_c_plus = int(r_c_plus['tag'], 16)
    tag = (tag_c_plus - diff * K_sqr) % p
    print(tag)

    tag = int.to_bytes(tag, 16, 'big')

    # Send the combined ciphertext with the forged signature to the server
    r_flag = snd_rcv({"command": "decrypt", "ciphertext": c.hex(), "nonce": nonce, "tag": tag.hex()})
    print(r_flag)
    print(r_flag['res'])
    

if __name__ == "__main__":
    main()
