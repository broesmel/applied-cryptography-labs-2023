#!/usr/bin/env python3

"""
This is a simple client implementation based on telnetlib that can help you connect to the remote server.

Taken from https://cryptohack.org/challenges/introduction/
"""

import telnetlib
import json

# Change this to REMOTE = False if you are running against a local instance of the server
REMOTE = True

# Remember to change the port if you are re-using this client for other challenges
PORT = 50221

if REMOTE:
    host = "aclabs.ethz.ch"
else:
    host = "localhost"


tn = telnetlib.Telnet(host, PORT)

def readline():
    return tn.read_until(b"\n")

def json_recv():
    line = readline()
    return json.loads(line.decode())

def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")

def snd_rcv(req):
    json_send()
    return json_recv()

if __name__ == "__main__":
    request = {
        "command": "intro"
    }
    json_send(request)

    response = json_recv()

    print(response)
