#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES


def xor(X: bytes, Y: bytes):
    return bytes(x ^ y for (x, y) in zip(X, Y))


tn = telnetlib.Telnet("aclabs.ethz.ch", 50401)

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
    # ECB mode encryption: same pt will encrypt to the same ct
    # token login structure as in the code below
    block_size = 16
    username = "0"*13
    favourite_coffee = "decaf"
    """ # NONE OF THE FOLLOWING IS NECESSARY :)
    # get a first token, with role=user isolated in a block, prepending 0s through username
    print(r0:= snd_rcv({"command": "register", "username": username, "favourite_coffee": favourite_coffee}))
    # becaus of the way the token is constructed, we can get the role=user block
    pt_token = "&".join(
                [
                    f"username={username}",
                    "role=user",
                    f"favourite_coffee={favourite_coffee}",
                ]
            )
    pts = [pt_token.encode()[i:i+16] for i in range(0, len(pt_token.encode()), 16)]
    print(pts)
    ct_token0 = bytes.fromhex(r0["token"])
    print(len(ct_token0))
    """
    # even easier, we don't need to modify anything we can just directly set the role=admin block in the username variable
    # as duplicated entries skipped, we can use this token directly to login
    username = f"00000&role=admin"
    print(r1:= snd_rcv({"command": "register", "username": username, "favourite_coffee": favourite_coffee}))
    ct_token1 = bytes.fromhex(r1["token"])

    print(l1:=snd_rcv({"command": "login", "token": ct_token1.hex()}))
    print(r:=snd_rcv({"command": "change_settings", "good_coffee": "true"}))
    print(r:=snd_rcv({"command": "get_coffee"}))

main()