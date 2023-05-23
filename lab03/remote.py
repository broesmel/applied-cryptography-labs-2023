#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

tn = telnetlib.Telnet("aclabs.ethz.ch", 50200)

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

if(__name__ == '__main__'):
    request = {
        "command": "intro".encode().hex()
    }
    json_send(request)

    response = json_recv()

    print(response)
