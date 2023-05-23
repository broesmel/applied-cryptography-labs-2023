#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json

"""
 M3: Suboptimal
200
graded interactive

For this challenge and the following one, you are given an oracle that encrypts and an oracle that decrypts a message using an RSA-based public-key encryption scheme.

The encryption algorithm takes a plaintext ptxt, pads it (using a custom, randomized padding scheme), and encrypts it using RSA. We provide a PDF containing a description and a diagram of the scheme, as well as the objective of the challenge.
nc aclabs.ethz.ch 51003
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
PORT = 51003
loco = 0
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)

# constants grabbed from the server code
TARGET = 256
RSA_KEYLEN = 1024 # 1024-bit modulus
RAND_LEN = 256 # 256-bit of randomness for masking
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8
c_len = RSA_KEYLEN // 8
msg_error_m0 = 'Error: Decryption failed'
msg_error_mr = 'Eror: Decryption failed'
msg_successy = 'Nom, nom, nom... This plaintext tasted nice!'

def oracle(c: int) -> bool:
    # send ciphertext to server and get response
    r_c  = snd_rcv({"command": "decrypt", 'ctxt': int.to_bytes(c, c_len, 'big') .hex()})
    # if we have error m0, then m_m[0] != 0
    # if we have error mr, then m_m[0] == 0
    if msg_error_m0 in r_c.get('error', ''):
        return True
    else: return False

def main():
    # Get the parameters from the server
    params = snd_rcv({"command": "get_params"})
    message = b"If you use textbook RSA I will find you and hunt you down (cit.)"
    N = params['N']
    e = params['e']
    print(f"{params=}, {N.bit_length()=}")
    for i in range(TARGET):
        challenge = snd_rcv({"command": "get_challenge"})
        # print(f"{challenge=}"[:8], end=' ')
        ctxt = bytes.fromhex(challenge['challenge'])
        ctxt_len = len(ctxt)
        c = int.from_bytes(ctxt, 'big')
        # c == pow(m, e, N)
        # m == pow(c, d, N)
        x = -1

        for x in range(1, RSA_KEYLEN):
            # encrypting 2^x gives us a bit-shift of x bits to the left in m 
            # when multiplied to our c, due to the homomorphic property of RSA
            # so we can use this to find the number of 0 bits before the first
            # 1 bit of the message (including the padding)
            m2 = pow(2, x, N)
            c2 = pow(m2, e, N)
            c_m = c * c2 % N

            if oracle(c_m):
                break

        # RSA_KEYLEN is the total ciphertext length in bits, so we can subtract
        # the number of bits we found to get the number of bits in the message
        # (including the padding), then subtract 8 for the leading 0 byte
        # then add 1 because the value we are looking for is before the first
        # error / 1 bit in the MSB
        
        bit_length = RSA_KEYLEN - 8 - x + 1 # subtract 8 for the leading 0 byte

        print(f"{bit_length=}, {x=}", end=' ')
        r_solve = snd_rcv({"command": "solve", 'i': bit_length})
        print(f"{r_solve=}", end='\n')
    
    r_flag = snd_rcv({"command": "flag"})
    print(r_flag)
    flag = r_flag['flag']
    print(flag)

    return


if __name__ == "__main__":
    main()
