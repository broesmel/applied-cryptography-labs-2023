#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json

# Copied from the server
import math
from typing import Tuple
from Crypto.Hash import MD5, HMAC, SHA256


"""
 M0: ENOENTROPY
200
graded interactive

    https://xkcd.com/221/

    Randomness is tricky, let's do everything deterministically!

You are given a (de-randomized) DSA signing oracle. The signature scheme "roughly" follows RFC 6979.

The server implements a signing oracle.

    The get_params command returns the DSA parameters and the server's public key (used to verify the signatures).
    The sign command returns a signature for a message of your choice. The server refuses to sign the messge "Give me a flag!".
    The flag command returns the flag, given a valid signature for the message "Give me a flag!". You may only call this command once.

Forge a signature for the message "Give me a flag!"!
nc aclabs.ethz.ch 51000 
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
PORT = 51000
loco = 0
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)

# implementation of the server
def get_nonce(msg: bytes, sign_key: int, g: int, p: int, q: int) -> Tuple[int, int]:
    # Because we don't trust our server, we will be hedging against randomness failures by derandomising

    h = MD5.new(msg).digest()

    # We begin by deterministically deriving a nonce
    # as specified in https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
    l = 8 * MD5.digest_size
    rlen = math.ceil(q.bit_length() / 8)
    V = bytes([1] * l)
    K = bytes([0] * l)

    K = HMAC.new(K, V + b'\x00' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()
    K = HMAC.new(K, V + b'\x01' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()

    while True:
        T = b''
        tlen = 0

        while tlen < q.bit_length():
            V = HMAC.new(K, V).digest()
            T += V
            tlen += len(V) * 8

        # Apply bits2int and bring down k to the length of q
        k = int.from_bytes(T, "big")
        k >>= k.bit_length() - q.bit_length()

        r = pow(g, k, p) % q

        if 1 <= k <= q-1 and r != 0:
            break

        K = HMAC.new(K, V + b'\x00').digest()
        V = HMAC.new(K, V).digest()

    return k, r


def DSA_sign(msg: bytes, sign_key: int, g: int, p: int, q: int):
    # Get k and r = (g^k mod p) mod q
    k, r = get_nonce(msg, sign_key, g, p, q)

    # Compute the signature
    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    s = (pow(k, -1, q) * (h + sign_key * r)) % q
    return r, s

def main():
    # Get the parameters from the server
    params = snd_rcv({"command": "get_params"})
    print(params)
    vfy_key = params['vfy_key']
    g = params['g']
    p = params['p']
    q = params['q']

    # In the server, the nonce is dependant on the MD5 hash of the message
    # in lab 5, we have already worked with MD5 collisions:
    c1 = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa200a8284bf36e8e4b55b35f427593d849676da0d1555d8360fb5f07fea2'
    c2 = '4dc968ff0ee35c209572d4777b721587d36fa7b21bdc56b74a3dc0783e7b9518afbfa202a8284bf36e8e4b55b35f427593d849676da0d1d55d8360fb5f07fea2'

    r_sign = snd_rcv({"command": "sign", "message": c1})
    print(r_sign)
    r1 = r_sign['r']
    s1 = r_sign['s']
    r_sign = snd_rcv({"command": "sign", "message": c2})
    print(r_sign)
    r2 = r_sign['r']
    s2 = r_sign['s']

    print(r1 == r2)
    # Now we have two messages with the same r value
    # Thus the k value is the same for both messages

    # We can recover k from the two signatures as shown in the lecture slides
    m1 = bytes.fromhex(c1)
    m2 = bytes.fromhex(c2)
    H_m1 = int.from_bytes(SHA256.new(m1).digest(), "big")
    H_m2 = int.from_bytes(SHA256.new(m2).digest(), "big")
    
    # s1 = k^-1 (H(m1) + x ⋅ r) mod q 
    # s2 = k^-1 (H(m2) + x ⋅ r) mod q
    # s1 - s2 = k^-1 (H(m1) - H(m2)) mod q
    # k = (s1 - s2)^-1 * (H(m1) - H(m2)) mod q
    # and from k, we can recover the private key x
    # x = k^-1 (s * k - H(m)) mod q
    k = ( pow(s1 - s2, -1, q) * (H_m1 - H_m2) ) % q
    x = pow(r1, -1, q) * (s1 * k - H_m1) % q

    # Now we can forge a signature for the message that will give us the flag
    m = b"Give me a flag!"
    # ... if it verifies
    r, s = DSA_sign(m, x, g, p, q)
    

    # Send the forged signature to the server
    r_flag = snd_rcv({"command": "flag", "r": r, "s": s})
    print(r_flag)
    print(r_flag['flag'])
    

if __name__ == "__main__":
    main()
