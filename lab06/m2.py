#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50602)

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

from shazam import SHAzam
COMMAND_STRING = b'command=hello&arg=world'

def m2():
    r=snd_rcv({"command": "get_token",})
    print(r)
    authenticated_command = bytes.fromhex(r['authenticated_command'])
    mac = bytes.fromhex(r['mac'])
    print(f"authenticated_command: {authenticated_command}, mac: {mac.hex()}")

    print(f"{snd_rcv({'command': 'authenticated_command', 'authenticated_command':authenticated_command.hex(), 'mac':mac.hex()})}")

    # begin with the original message of length L bits
    # append a single '1' bit
    # append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
    # append L as a 64-bit big-endian integer, making the total post-processed length a multiple of 512 bits



    cipher_key_cmd = SHAzam()
    for i, b in enumerate(blockify(mac, 4)):
        cipher_key_cmd.hash[i] = int.from_bytes(b, "big") 
        print(f"cipher_key_cmd.hash[{i}] = {cipher_key_cmd.hash[i].to_bytes(4, 'big').hex()}")

    suffix = b'&command=flag'

    length = len(authenticated_command)
    print(length)
    remainder_bytes = (length + 8) % 64
    filler_bytes = 64 - remainder_bytes
    zero_bytes = filler_bytes - 1
    encoded_bit_length = (8 * length).to_bytes(8, "big")
    padding = b'\x80' + b'\x00' * zero_bytes + encoded_bit_length

    
    padding = bytes.fromhex('80000000000000000000000000000000000000000000000138')

    suffix = suffix * 8

    authenticated_command_padded_extended = authenticated_command + padding + suffix
    cipher = SHAzam()
    cipher.hash  = cipher_key_cmd.hash

    print(f"{padding.hex()=}")


    print(f"prior: {b''.join([i.to_bytes(4, 'big') for i in cipher.hash]).hex()}")
    cipher.update(suffix)
    print(f"u sfx: {b''.join([i.to_bytes(4, 'big') for i in cipher.hash]).hex()}")

    # new_hash = cipher.digest()
    cipher.update(bytes.fromhex('800000000000000000000000000000000000000000000540'))
    print(f"u pad: {b''.join([i.to_bytes(4, 'big') for i in cipher.hash]).hex()}")

    new_hash = b''.join([i.to_bytes(4, 'big') for i in cipher.hash])
    
    print(authenticated_command_padded_extended, new_hash.hex())

    
    print(f"{snd_rcv({'command': 'authenticated_command', 'authenticated_command':authenticated_command_padded_extended.hex(), 'mac':new_hash.hex()})}")


m2()