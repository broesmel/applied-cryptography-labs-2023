#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("graded.aclabs.ethz.ch", 50606)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r

def blockify(a, blocksize=16):
    return [a[i : i + blocksize] for i in range(0, len(a), blocksize)]

def snd_rcv(req):
    json_send(req)
    return json_recv()

def padding_bytes(input_len):
    remainder_bytes = (input_len + 8) % 64
    filler_bytes = 64 - remainder_bytes
    zero_bytes = filler_bytes - 1
    encoded_bit_length = (8 * input_len).to_bytes(8, "big")
    return b"\x80" + b"\0" * zero_bytes + encoded_bit_length


def m0():
    r=snd_rcv({"command": "token",})
    print(r)
    token = r["token"]
    command_string = bytes.fromhex(token['command_string'])
    mac = bytes.fromhex(token['mac'])
    print(f"command_string: {command_string}, mac: {mac}")

    print(f"{snd_rcv({'command': 'token_command', 'token':token})}")

    # begin with the original message of length L bits
    # append a single '1' bit
    # append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    # append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits


    tn_hashpump = telnetlib.Telnet("aclabs.ethz.ch", 50690)
    cmd = {
        "command": "hashpump",
        "mac": mac.hex(),
        "data": command_string.decode(),
        "append": b"&command=flag".decode(),
    }
    tn_hashpump.write(json.dumps(cmd).encode() + b"\n")
    r = json.loads(tn_hashpump.read_until(b"\n").decode())
    print(r)

    new_mac = bytes.fromhex(r['new_hash'])
    new_command_string = bytes.fromhex(r['new_data'])
    
    new_token = {'mac': new_mac.hex(), 'command_string': new_command_string.hex()}

    print(snd_rcv({'command': 'token_command', 'token': new_token}))

m0()