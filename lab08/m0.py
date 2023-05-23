#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes

from rsa import rsa_key_gen, rsa_enc, rsa_dec


"""
To get the flag for this challenge complete the rsa.py implementation and then:

    use the function rsa_key_gen you just implemented to set the RSA parameters with the command set_parameters
    use the function rsa_dec you just implemented to decrypt the encrypted flag you get with the command encrypted_flag

nc aclabs.ethz.ch 50800 
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

tn = telnetlib.Telnet("aclabs.ethz.ch", 50800)

def main():
    (pk, sk, primes) = rsa_key_gen(2048)
    (N, e) = pk
    (p, q) = primes
    d = sk[1]

    msg = {
        "command": "set_parameters",
        "N": N,
        "e": e,
        "d": d,
        "p": p,
        "q": q
    }

    r_param = snd_rcv(msg)
    print(r_param)

    r_flag = snd_rcv({"command": "encrypted_flag"})
    print(r_flag)
    flag_enc = int(r_flag['res'].split(' ')[-1])

    flag_int = rsa_dec(sk, flag_enc)
    flag = long_to_bytes(flag_int).decode()
    print(flag)

if __name__ == "__main__":
    main()
