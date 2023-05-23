#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

import secrets

"""
They say that leaking metadata isn't that bad. Today we shall prove them wrong.

The server implements a messaging application, with message serialization and deserialization. Messages are encrypted using AES in IGE mode. You are given a "metadata" oracle that leaks sender, receiver and other values. The oracle accepts up to 128 queries (even failed ones count!). Find a way to recover the secret message, which is in the additional_metadata field of the message. If you manage to do so, you obtain the flag.

The init command returns an AES-IGE encrypted message composed of a fixed protocol header, a metadata block and a single additional_metadata block, which contains the secret message.
The metadata_leak command takes an encrypted message, decrypts it and, if parsing succeeds, leaks some metadata fields of the message: sender, receiver, timestamp and protocol version (but not the additional_metadata).
The flag command takes a guess for the secret message. If the guess is correct, it returns the flag. Otherwise, it closes the connection.
"""


def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]



tn = telnetlib.Telnet("aclabs.ethz.ch", 50404)

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
    file_name = f""
    data = (b"A"*10 + b"&flag="+bytes([0]*16)+ b"A"*10)
    flag_test = bytes([0]*16)
    ptxt = (
        b"filename="
        + file_name.encode()
        + b"&data="
        + data
        + b"&flag="
        + flag_test
    )

    # block 1 and block 3 are identical!
    ptxt_pad = pad(ptxt, block_size)

    # CBC decryption works like this:
    # P0 = D(C0) xor iv
    # Pi = D(Ci) xor Ci-1
    # encryption:
    # Ci = E(Pi xor Ci-1)


    # we can construct a text to be decrypted with every part known except the byte,
    # with input possibilities. thus we can construct a list of 0x100 possibilities
    # where we set the last byte to the input possibilities and the rest to all 0s.
    # to extend over m3: we recover the flag byte by byte by moving the flag 
    # into a specific block 1 byte at a time, creating a data tag to match and repeating
    # m3's solution
    # print(ptxt_pad, blockify(ptxt_pad), len(ptxt_pad))
    
    data_32 = bytes([0]*11)
    # to get the len of the flag, compare with smallest ptxt to send:
    ptxt_32 = (
        b"filename="
        + b"&data="+data_32
        + b"&flag="
    )

    # find out the length of the flag, to know how long to go and not rely on special characters in the flag or so...
    r=snd_rcv({"command": "encrypt", "file_name": '', "data": data_32.hex()})
    len_ctxt_32 = len(bytes.fromhex(r['ctxt']))
    len_flag_max = len_ctxt_32-len(ptxt_32)
    print(f"{len_ctxt_32=}")
    print(f"{len(ptxt_32)=}")
    print(f"{len_flag_max=}")
    
    l = 0
    cur_len = len_ctxt_32
    while(cur_len == len_ctxt_32):
        r=snd_rcv({"command": "encrypt", "file_name": "", "data": (data_32+bytes([0]*l)).hex()})
        cur_len = len(bytes.fromhex(r['ctxt']))
        l += 1

    print(f"{l=}")

    # flag comes last, adjust for padding
    len_flag = len_flag_max-(l-1)
    print(f"{len_flag_max=}")
    print(f"{len_flag=}") 

    flag = b''
    
    for i in range(len_flag):
        for x in range(0x100):
            # needs to be empty we do it using the data tag
            file_name = f""
            # match format of later block, append trailing b"A" in order to match format
            data = (
                b"A"*(26+len_flag_max-i) + # initial padding 
                b"&flag=" + flag + bytes([x]+[0]*(len_flag_max-(i+1))) + # last byte of current block
                b"A"*(10) # trailing padding
                )
            # print(blockify(data))
            r=snd_rcv({"command": "encrypt", "file_name": file_name, "data": data.hex()})
            # ptxt really is the 'ctxt' here. we use byte 0 as the key bytes so we don't accidentally xor it
            ptxt_no_flag = (
                    b"filename="
                    + file_name.encode()
                    + b"&data="
                    + data
                    + b"&flag="
            )
            iv = bytes.fromhex(r["iv"])
            # ctxt really is ptxt!
            ctxt = bytes.fromhex(r["ctxt"])
            ctxt_blocks = blockify(ctxt)
            
            flag_test = flag + bytes([0]*(len_flag_max-i))
            ptxt = pad(ptxt_no_flag+ flag_test, 16)
            ptxt_blocks = blockify(ptxt)
            # print(ptxt_blocks)

            # blocks to compare
            rel_block_ind_0 = len_flag_max//16 + 2
            rel_block_ind_1 = len(ptxt_no_flag)//16 + i//16
            print(ptxt_blocks[rel_block_ind_0], ptxt_blocks[rel_block_ind_1], len(ptxt_blocks), len(ctxt_blocks), end='\r')

            # xor the result with the iv and the blocks we send over to get D(b) for each block
            # actually, just do it for the relevant blocks:
            decr_blocks=dict()
            # len_ctxt_blocks = len(ctxt_blocks)
            # for j in range(0, len_ctxt_blocks):
            #     if(j ==0):
            #         decr_blocks.append(xor(iv, ctxt_blocks[j]))
            #     else:
            #         decr_blocks.append(xor(ptxt_blocks[j-1], ctxt_blocks[j]))

            decr_blocks[rel_block_ind_0] = xor(ptxt_blocks[rel_block_ind_0-1], ctxt_blocks[rel_block_ind_0])
            decr_blocks[rel_block_ind_1] = xor(ptxt_blocks[rel_block_ind_1-1], ctxt_blocks[rel_block_ind_1])

            # print([b.hex() for b in ptxt_blocks], end='\r')
            # print([b.hex() for b in ctxt_blocks], end='\r')
            # print([b.hex() for b in decr_blocks], end='\r')

            # if D(b) of our secret_byte construction matches the one by the server, we found the current byte of the flag!
            if decr_blocks[rel_block_ind_0] == decr_blocks[rel_block_ind_1]:
                flag += bytes([x])
                print('--------------found!!', bytes([x]), flag, '--------------')
                break

    print(flag)
        
main()

"""
This problem extends on M3. You should solve that challenge first.

Again, you can use the encrypt command to provide a file name and some data to the server. This time, the server appends the flag (instead of a secret byte) to the plaintext before encrypting. Your objective is to recover that flag.

nc aclabs.ethz.ch 50404
"""