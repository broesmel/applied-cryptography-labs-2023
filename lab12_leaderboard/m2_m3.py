#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes

# from the server
from typing import Tuple

import gzip
import time
import json
import math
import secrets

from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.number import inverse


"""
 M2: A True Cryptographer - 1st Flag
100

    A true cryptographer never sleeps. Enjoy your weekend.

EigenBackups is a company specialized in "zero-knowledge backups": they allow you to upload your data to their servers, encrypted with your own keys. The CEO claims that, because they don't have their clients' keys, they cannot decrypt any of their data. Once again, today we shall prove them wrong.

You have been asked to conduct a security assessment of their infrastructure. You will start as a network attacker. From the TrueCryptographerControlPanel class you can send and intercept messages between the client and the server. Your final objective is to recover the contents of the user backups.

On a high level, the protocol works as follows: 1. The client and the server execute an authenticated key-exchange to derive symmetric keys 2. The client and the server will then exchange messages, encrypted with the session keys 3. Every 10 minutes, the client can execute two backups, each of which contains one flag.

This challenge thus contains two flags: submit here the flag for backup1 and submit the flag for backup2 in challenge M3.

Think outside of the box. Don't be afraid to break the rules. Where we're going we don't need rules, only flags.

Note that this challenge is more complex than most other challenges you have previously seen. This is to show you how one would begin analyzing cryptographic protocols "in-the-wild". This requires you to understand all the interplays between multiple protocols and how to break them.
nc aclabs.ethz.ch 51202 

Hints:
You should try to first break the AKE protocol in order to be able to send messages to the client
I hate pycryptodome, but I love Doctor Who. Perhaps a hint in-verses would be helpful to you?
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
PORT = 51202
loco = 1
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)


# from the server code
# Every BACKUP_TIME_INTERVAL seconds, the client may try to backup data
BACKUP_TIME_INTERVAL = 600

# Parameters of the NIST P-256 curve
CURVE_NAME = "NIST P-256"
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
G = ECC.EccPoint(
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

# Size of the counter in bytes in the associated data
COUNTER_SIZE = 32

# The number of bytes required to represent a field element (e.g. a coordinate)
FIELD_ELEM_BYTES = math.ceil(q.bit_length() / 8)

def EccKey_to_bytes(key: ECC.EccKey) -> bytes:
    x = int(key.pointQ.x).to_bytes(FIELD_ELEM_BYTES, "big")
    y = int(key.pointQ.y).to_bytes(FIELD_ELEM_BYTES, "big")
    return x + y


def EccKey_from_bytes(key_bytes: bytes) -> ECC.EccKey:
    x = int.from_bytes(key_bytes[:FIELD_ELEM_BYTES], "big")
    y = int.from_bytes(key_bytes[FIELD_ELEM_BYTES:], "big")
    return ECC.construct(curve=CURVE_NAME, point_x=x, point_y=y)


def ECDSA_sign(msg: bytes, key: ECC.EccKey) -> Tuple[int, int]:
    d = int(key.d)
    h = int.from_bytes(SHA256.new(msg).digest(), "big")

    while True:
        k = secrets.randbelow(q - 1) + 1
        K = G * k
        r = int(K.x) % q

        if r == 0:
            continue

        s = (inverse(k, q) * (h + r * d)) % q

        if s != 0:
            return r, s


def ECDSA_verify(msg: bytes, r: int, s: int, key: ECC.EccKey) -> bool:
    # Bring r, s to the correct range
    r %= q
    s %= q

    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    u1 = (h * inverse(s, q)) % q
    u2 = (r * inverse(s, q)) % q
    P = G * u1 + key.pointQ * u2
    return r == P.x


def main():

    # to trick this:
    """
    f_hlo = {'resp': "Hi Bob, I'm Alice. This is my public key", 'alice_key': 1}

    r_b_init = snd_rcv({"command": "bob_initialisation", 'alice_hello': f_hlo})
    print(r_b_init)
    b_pub = r_b_init["bob_key"]
    b_hlo = {'resp': r_b_init["resp"], 'bob_key': b_pub}

    r_a_init = snd_rcv({"command": "alice_initialisation"})
    print(r_a_init)
    a_pub = r_a_init["alice_key"]
    a_hlo = {'resp': r_a_init["resp"], 'alice_key': a_pub}

    e_hlo = {'resp': "Hi Alice, I'm Bob. This is my public key", 'bob_key': 1}


    r_a_fin = snd_rcv({"command": "alice_finished", 'bob_hello': e_hlo})
    print(r_a_fin)
    # => shared keys are both 1
    """
    # send hello to server using point equivalent to 1
    # receive pubkey from server 
    # send hello to client using point equivalent to 1
    # receive pubkey from client
    # send finished to client


    # AKE protocol normal flow
    """
    r_client_hello = snd_rcv({"command": "start_ake"})
    print(r_client_hello)
    client_hello_eph_pubkey = bytes.fromhex(r_client_hello["intercepted_payload"]["pubkey"])
    client_hello_signature = r_client_hello["intercepted_payload"]["signature"]
    client_hello_r = r_client_hello["intercepted_payload"]["signature"]["r"]
    client_hello_s = r_client_hello["intercepted_payload"]["signature"]["s"]

    r_server_hello = snd_rcv({"command": "send_message_to_server", "message": {"pubkey": client_hello_eph_pubkey.hex(), "signature": client_hello_signature}})
    print(r_server_hello)

    server_hello_eph_pubkey = bytes.fromhex(r_server_hello["intercepted_payload"]["pubkey"])
    server_hello_signature = r_server_hello["intercepted_payload"]["signature"]
    server_hello_r = r_server_hello["intercepted_payload"]["signature"]["r"]
    server_hello_s = r_server_hello["intercepted_payload"]["signature"]["s"]

    client_server_hello_done = snd_rcv({"command": "send_message_to_client", "message": {"pubkey": server_hello_eph_pubkey.hex(), "signature": server_hello_signature}})
    print(client_server_hello_done)
    # AKE protocol done
    """

    # AKE protocol with MITM
    r_client_hello = snd_rcv({"command": "start_ake"})
    print(r_client_hello)
    client_hello_eph_pubkey = bytes.fromhex(r_client_hello["intercepted_payload"]["pubkey"])
    client_hello_signature = r_client_hello["intercepted_payload"]["signature"]

    # generate invalid curve point
    # find u s.t. u is the upper limit of x for Q = x * G
    # i.e. find u s.t. u * Q = 0
    Q = EccKey_from_bytes(client_hello_eph_pubkey).pointQ
    u = 1
    while not Q.is_point_at_infinity():
        Q = Q + G
        u += 1
        print(u, Q, end="\r")
    print(u)

    r_server_hello = snd_rcv({"command": "send_message_to_server", "message": {"pubkey": client_hello_eph_pubkey.hex(), "signature": client_hello_signature}})
    print(r_server_hello)


















    server_CREATE_BACKUP = snd_rcv({"command": "send_message_to_server", 
        "message": 
        {
            "payload": b"decrypts_w_tag_to_msg_dict".hex(),
            "nonce": b"\x00\x00\x00".hex(),
            "tag": b"\x00\x00\x00".hex()},
        }
    )
    print(server_CREATE_BACKUP)
    




    # vulnerabilities from the m2_m3/server/server.py:
    # the nonce1 for the backup1 is only 3 bytes long
    salt = "all these flavours and you choose to be salty"
    # master_secret = scrypt(self.password, salt, 32, N=2**20, r=8, p=1)



if __name__ == "__main__":
    main()
