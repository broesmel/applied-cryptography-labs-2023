#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes


from rsa import rsa_key_gen, rsa_enc, rsa_dec

"""
I really like RSA and today I feel generous, here is a decryption oracle for you!
nc aclabs.ethz.ch 50801 
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

tn = telnetlib.Telnet("aclabs.ethz.ch", 50801)

def main():
    r_flag = snd_rcv({"command": "encrypted_flag"})
    print(r_flag)
    flag_enc = int(r_flag['encypted_flag'], 16)
    N = int(r_flag['N'], 16)
    e = int(r_flag['e'], 16)
    pk = (N, e)

    mod = 999
    mod_enc = rsa_enc(pk, mod)

    flag_enc_mod = flag_enc * mod_enc

    r_dec = snd_rcv({"command": "decrypt", "ciphertext": hex(flag_enc_mod)[2:]})
    print(r_dec)
    flag_mod = int(r_dec['res'], 16)
    flag = flag_mod // mod
    print(long_to_bytes(flag))

if __name__ == "__main__":
    main()
