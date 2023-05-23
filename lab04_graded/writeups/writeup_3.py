#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

import secrets

def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]



tn = telnetlib.Telnet("aclabs.ethz.ch", 50403)

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
    # CBC mode DECRYPTION instead of encryption, 
    block_size = 16
    i = 0xff
    file_name = f"aaa"
    data = (b"&secret_byte="+bytes([i])+b"a=").hex()
    sb_test = bytes([0])
    ptxt = (
        b"filename="
        + file_name.encode()
        + b"&data="
        + bytes.fromhex(data)
        + b"&secret_byte="
        + sb_test
    )
    ptxt_pad = pad(ptxt, block_size)

    k_test = secrets.token_bytes(16)
    cipher = AES.new(k_test, AES.MODE_CBC, iv=k_test)
    p = cipher.decrypt(ptxt_pad)
    print(p)    
    # CBC decryption works like this:
    # P0 = D(C0) xor iv
    # Pi = D(Ci) xor Ci-1
    # encryption:
    # Ci = E(Pi xor Ci-1)


    # we can construct a text to be decrypted with every part known except the byte,
    # with input possibilities. thus we can construct a list of 0xff possibilities
    # where we set the last byte to the input possibilities and the rest to all 0s.
    print(ptxt_pad, blockify(ptxt_pad), len(ptxt_pad))

    # do the above 10 times
    for i in range(10):
        secret_byte = b''
        for x in range(0x100):
            # needs to be length 3 and end with b"a" to match the block containing the actual secret byte,
            # as per the below construction
            file_name = "aaa"
            # match format of later block, append trailing b"a=" in order to match format of 'data=' tag
            data = (b"&secret_byte="+bytes([x])+b"a=")
            # make sure fits 1 block
            #print(blockify(data))
            r=snd_rcv({"command": "encrypt", "file_name": file_name, "data": data.hex()})
            # ptxt really is the 'ctxt' here. we use byte 0 as the secret byte so we don't accidentally xor it
            ptxt = pad(
                    b"filename="
                    + file_name.encode()
                    + b"&data="
                    + bytes.fromhex(data.hex())
                    + b"&secret_byte="
                    + bytes([0])
            , 16)
            iv = bytes.fromhex(r["iv"])
            # ctxt really is ptxt!
            ctxt = bytes.fromhex(r["ctxt"])
            ctxt_blocks = blockify(ctxt)
            
            # xor the result with the iv and the blocks we send over to get D(b) for each block
            decr_blocks=[]
            for j in range(0, len(ctxt_blocks)):
                if(j ==0):
                    decr_blocks.append(xor(iv, ctxt_blocks[j]))
                else:
                    decr_blocks.append(xor(blockify(ptxt)[j-1], ctxt_blocks[j]))


            print([b.hex() for b in blockify(ptxt)], end='\r')
            print([b.hex() for b in ctxt_blocks], end='\r')
            print([b.hex() for b in decr_blocks], end='\r')

            # if D(b) of our secret_byte construction matches the one by the server, we found it!
            if decr_blocks[1] == decr_blocks[2]:
                secret_byte = bytes([x])
                print('found!!', secret_byte)
                break

        print(r:=snd_rcv({"command": "solve", "solve": secret_byte.hex()}))
    
    print(r:=snd_rcv({"command": "flag"}))


main()

"""
    Welcome to our EaaS (Encryption-as-a-Service) platform. You give us a file, we decrypt it! Uh... I mean encrypt it! You also get a tasty little flag, as a treat.

You are given an "encryption" oracle that allows you partial control of the plaintext. Alongside the plaintext, the server includes a single secret byte. Your objective is to recover that secret byte. You must be able to guess the correct byte 10 times in a row.

    The encrypt command takes a file_name and hex-encoded data. It then formats the plaintext accordingly and appends a secret byte to it. Finally, it returns the corresponding ciphertext.
    The solve command takes your hex-encode guess for the secret byte. If your guess is correct, it increments your score. Otherwise, the server closes the connection.
    When you have reached the target score of 10 consecutive guesses, use the flag command to retrieve the flag.

nc aclabs.ethz.ch 50403 
"""