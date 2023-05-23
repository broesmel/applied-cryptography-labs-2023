#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json
from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


import datetime
import numpy
import time
import random

"""
 M6: Punny title
100
RSA

Presenting my novel key generation algorithm!

By selecting the seeds manually, I ensure that for any two private keys (p,q) and (p',q') I generate, p and p' will be generated from the same seed if and only if q and q' will be generated from the same seed.
nc aclabs.ethz.ch 50806 

My entropy is chef kiss
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

PORT = 50806

loco = 0

host = "aclabs.ethz.ch"
if loco:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

class self:
    def make_random_stream(seed: int):
        """Use Numpy to generate a random stream from a specific seed. 
        Because I multiply it by 16 random bytes this must be secure."""
        numpy.random.seed(0)
        return lambda n: numpy.random.bytes(n)


def main():
    E = 65537
    delta_max = 20
    ts = []
    while True:
        print("Waiting for timing...................................", end="\r")
        while(len(ts) < 3):
            t = datetime.datetime.now().second
            if t in list(range(1,delta_max)): # t-1 == 0 or t-2 == 0 or t-3 == 0:
                r_gen = snd_rcv({"command": "generate"})
                # print(r_gen)

                    
                N = int(r_gen["N"])
                i = int(r_gen["key_index"])
                ts.append((i, t, N))
                print(f"Received key {i=} on {t=}; N={str(N)[:3]}")
            else:
                wait = 60-t-1-delta_max
                if wait>0:
                    print(f"Waiting for timing... {wait=}s", end="\r")
                    time.sleep(wait)

        while ts:
            k =  ts.pop(0)
            m = None
            i = k[0]
            t = k[1]
            N = k[2]
            r_enc = snd_rcv({"command": "encrypt", "index": i})
            c = bytes.fromhex(r_enc["encrypted_flag"])
            try:
                p = number.getPrime(1024, randfunc=self.make_random_stream(0))
                q = N // p
                phiN = (p-1)*(q-1)
                d = number.inverse(E, phiN)

                key = RSA.construct((N, E, d))
                cipher = PKCS1_OAEP.new(key)
                m = cipher.decrypt(c)
                print(m)
                if b'flag' in m:
                    return
            except Exception as e:
                print(e, "failed")
                continue
            finally:
                if not m:
                    print(f"Failed to decrypt with {k[0]=} on {t=}")
                elif b'flag' in m:
                    print(f"Decrypted with {k[0]=} on {t=}, got {m=}")
                    return
        # print("Sleeping for 30 seconds")
        # time.sleep(30)




if __name__ == "__main__":
    main()
