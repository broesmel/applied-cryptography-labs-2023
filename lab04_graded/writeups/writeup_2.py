#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def xor(X: bytes, Y: bytes):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50402)

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


def main():
    # from the server code:
    # ECB mode encryption extended by the IGE mode
    block_size = 16
    print(r0:= snd_rcv({"command": "flag"}))

    ctxt = bytes.fromhex(r0['ctxt'])
    m0 = bytes.fromhex(r0['m0'])
    c0 = bytes.fromhex(r0['c0'])
    print(len(ctxt), len(m0))

    # padding incorrect: 'error' is returned
    print(r:=snd_rcv({"command": "decrypt", "ctxt": bytes([0]*16).hex(), "m0": bytes([0]*16).hex(), "c0": bytes([0]*16).hex()}))
    # padding correct: 'res' is returned
    print(r:=snd_rcv({"command": "decrypt", "ctxt": r0['ctxt'], "m0": r0['m0'], "c0": r0['c0']}))
    # even though no plaintext is given, the server still error information: 
    # => we have a padding oracle!
    
    # decryption of ciphertext C = C1, ..., Cn works like this:
    # P0 = Dec(C0 xor m0)   xor c0
    # Pi = Dec(Ci xor Pi-1) xor Ci-1
    # like CBC, so we can process a ciphertext 2 blocks at a time,
    # do this 2-block by 2-block until we have the whole plaintext
    # modifying c0 until we get correct padding, then xoring by the padding to get the plaintext
    ptxt = b''
    for i in range(0, len(ctxt), block_size):
        if i == 0: # intial block: use the values as given by the server
            m_prev = m0
            c_prev = c0
        else: 
            m_prev = ptxt[i - block_size:i]
            c_prev = ctxt[i - block_size:i]
        
        c_curr = ctxt[i:i + block_size]

        # brute force of the current block
        brute = b''
        for j in range(block_size):
            for x in range(0x100):
                # craft a c0 by enumerating values for the padding, make sure to xor with the current byte position
                # moving in from the right
                c_prev_mod = (
                    bytes([0]*(block_size-(j+1))) +
                    xor(
                        bytes([j+1]*(j+1)), 
                        bytes([x]) + brute
                    )
                )
                # check our padding oracle based on the error information as above
                r=snd_rcv({"command": "decrypt", "ctxt": c_curr.hex(), "m0": m_prev.hex(), "c0": c_prev_mod.hex()})
                print(repr(r)[:0x40],'...', end='\r')
                if r.get('res', False):
                    print(repr(r)[:0x40], 'found', )
                    brute = bytes([x]) + brute
                    break
        # xor with c_prev to get the plaintext
        brute = xor(c_prev, brute)
        ptxt += brute

    # print the decrypted flag
    print('\n', ptxt.decode())

    

main()