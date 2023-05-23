import json

from telnetlib import Telnet
from typing import List

from eccrypto import ECDSA

REMOTE = 0

ECDSAinstance = ECDSA()
ECDSAinstance.keygen()


"""
 M1: ECDSA
100
ECDSA Interactive

    Welcome to European Cryptocurrency (ECC) AG! You have just been hired by us to implement and test elliptic curve cryptosystems. Your second task here is to implement ECDSA.

Now that we have an implementation of elliptic curve to work with, we can build ECDSA from there. You should be using SHA256 as the hash function. A code template can be found in eccrypto.py. (Use the elliptic curve implementation from the m0.x challenges)

Once you are happy with your implementation, here is what you need to do to capture the flag from the server (server.py). We provide a remote.py file which will help you to interact with the server.

    Obtain a challenge (explained later) from the server. The client should send a json file to the server with the following structure:

  {
      "command": "signed_command",
      "signed_command": {"command": "get_challenge"},
      "public_point": compressed public key of the client (hex string),
      "r": first component of the signature (hex string) for the message ("msg"),
      "s": second component of the signature (hex string) for the message ("msg")
  }

    Up on verifying the message from the client, the server generates a challenge as follows:

    Set up a sequence of messages "0", "1", ...
    For each message, the server signs it and generate a json with the following structure

{
    "msg": ,
    "r": ,
    "s":
}

    Some signature generated in step 2 will be fake signatures
    The server returns the challenge in a json with the following structure

{
    "public_point": compressed public key of the server (hex string),
    "challenge": a list of messages and signatures specified in step 2
}

    The client verifies the challenge signatures locally. To get the flag, the client sends a json to the server with the following structure:

 {
     "command": "signed_command",
     "signed_command": {
         "command": "backdoor",
         "solution": a list of bool which indicates the success/failure of the verification of the signatures},
     "public_point": compressed public key of the client (hex string),
     "r": first component of the signature (hex string) for the message ("msg"),
     "s": second component of the signature (hex string) for the message ("msg")
 }

nc aclabs.ethz.ch 51101 

"""


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def signed_json_send(tn: Telnet, req: dict):
    req_str = json.dumps(req)

    public_point_compressed_bytes = ECDSAinstance.public_point.to_bytes(
        compression=True
    )
    signature = ECDSAinstance.sign(req_str.encode())

    obj = {
        "command": "signed_command",
        "signed_command": req,
        "public_point": public_point_compressed_bytes.hex(),
        "r": signature[0].hex(),
        "s": signature[1].hex(),
    }
    json_send(tn, obj)


# Use the following 3 functions to send commands to the server
def get_status(tn: Telnet):
    obj = {"command": "get_status"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_challenge(tn: Telnet):
    obj = {"command": "get_challenge"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def reply_challenge(tn: Telnet, solution: List[bool]):
    obj = {"command": "backdoor", "solution": solution}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def attack(tn: Telnet):
    """Your attack code goes here."""

    status = get_status(tn)
    print(status)
    r_challenge = get_challenge(tn)
    challenge = r_challenge["challenge"]
    public_point = bytes.fromhex(r_challenge["public_point"])

    secretBits = []
    for c in challenge:
        m = c["msg"].encode()
        r = bytes.fromhex(c["r"])
        s = bytes.fromhex(c["s"])

        # print(m, r, s, public_point)

        b = ECDSAinstance.verify(m, r, s, public_point)
        secretBits.append(int(b))
        print(secretBits, end="\r")

    r_reply = reply_challenge(tn, secretBits)

    print()
    print(r_reply)

if __name__ == "__main__":
    REMOTE = 1
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51101
    with Telnet(HOSTNAME, PORT) as tn:
        attack(tn)
