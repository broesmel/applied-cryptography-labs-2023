#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from gmpy2 import iroot

from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from random import randint

from rsa import rsa_dec

import math

"""
 M3: Does size matter?
100

(a+b)(a-b) = a^2 - b^2

Damn, foiled again! I have fixed my parameters, implemented a faster key generation and used OAEP which is provably secure!
nc aclabs.ethz.ch 50803 
"""

_1_50 = 1 << 50  # 2**50 == 1,125,899,906,842,624

def isqrt(x):
    """Return the integer part of the square root of x, even for very
    large integer values."""
    if x < 0:
        raise ValueError('square root not defined for negative numbers')
    if x < _1_50:
        return int(math.sqrt(x))  # use math's sqrt() for small parameters
    n = int(x)
    if n <= 1:
        return n  # handle sqrt(0)==0, sqrt(1)==1
    # Make a high initial estimate of the result (a little lower is slower!!!)
    r = 1 << ((n.bit_length() + 1) >> 1)
    while True:
        newr = (r + n // r) >> 1  # next estimate by Newton-Raphson
        if newr >= r:
            return r
        r = newr
    
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

tn = telnetlib.Telnet("aclabs.ethz.ch", 50803)



def main():
    # from server.py
    # (p - 1) % 3 != 0
    # (q - 1) % 3 != 0
    # => (p - 1 ) * (q - 1)

    perc = 0.1
    exp = 0

    r_flag = snd_rcv({"command": "encrypted_flag"})
    print(r_flag)
    flag_enc = bytes.fromhex(r_flag['ctxt'])
    N = int(r_flag['N'])
    e = int(r_flag['e'])
    pk = (N, e)

    print()

    while(True):
        exp += 1
        # N = p * q

        # case 1: q = p + 2
        # N = p * (p + 2)
        # N = p^2 + 2p
        # 0 = p^2 + 2p - N
        # p = (-2 +- sqrt(4 + 4N)) / 2
        # p = -1 +- sqrt(1 + N)
        # p = sqrt(1 + N) - 1
        # phiN = (p - 1) * (q - 1)
        # phiN = (p - 1) * (p + 1)
        # phiN = p^2 - 1

        # case i q = p + 2i
        # N = p * (p + 2i)
        # N = p^2 + 2ip
        # 0 = p^2 + 2ip - N

        # 0 = (p+2i)(p+0)

        # p = (-2i +- sqrt(4i^2 + 4N)) / 2
        # p = -i +- sqrt(i^2 + N)
        # p = sqrt(i^2 + N) - i

        # N = p * q
        # N = p * (p + 2i)
        # phiN = (p - 1) * (q - 1)
        # phiN = (p - 1) * (p + 2i - 1)



        p = isqrt(N + exp**2) - exp
        q = p + 2 * exp
        if (p - 1) % e == 0 or (q - 1) % e == 0: continue
        phiN = (p - 1) * (q - 1)


        try:
            d = number.inverse(e, phiN)
        except ValueError as error:
            print(exp, error)
            continue
        sk = (N, d)

        print(f"{q-p=}")

        try:
            key = RSA.construct((N, e, d, p, q))
        except ValueError as error:
            print(exp, error)
            continue
        cipher = PKCS1_OAEP.new(key)
        flag = cipher.decrypt(flag_enc)
        if b'flag' in flag:
            print(flag)
            return
    
    print('\nfailed')


if __name__ == "__main__":
    main()
