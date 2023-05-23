#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes

from elgamal import ElGamalImpl

"""
 M1: ElGamal IoT Carpet
100
interactive

    Aladdin Trades GmbH is ready to launch its new product: an IoT Carpet.

    24 hours before the launch, the security team is scrambling to get all the cryptography in their device right.

You are given the server code (server.py) running on each Carpet.

Each server has a (public, secret) keypair, and accepts plaintext and encrypted commands. The encrypted commands are encrypted under its public key with the ElGamal public key encryption scheme. The public key of the Carpet can be obtained using the command get_public_key. The encrypted commands will be interpreted and will produce a response (or an error message). The responses (resp. error messages) will be encrypted (again, using ElGamal) using a public key chosen by the client. The client can set this public key using the command set_response_key.

As a warmup, implement ElGamal and talk to the Carpet! The backdoor encrypted command will give you a flag. Follow Section 2 of the original ElGamal (paper)[https://caislab.kaist.ac.kr/lecture/2010/spring/cs548/basic/B02.pdf] for implementing the scheme. When generating ElGamal keys, always use Crypto.PublicKey.ElGamal.generate(bits, randfunc) (docs)[https://pycryptodome.readthedocs.io/en/latest/src/public_key/elgamal.html].

Refer to the server code for the message format. Here is an example encrypted interaction between the client and the Carpet:

{'command': 'encrypted_command', 'encrypted_command': {'c1': '390b1ebfc6b8a730b003b423b384038f081e3cd6767c4e0d92f53487a93d0cca26fc48bb92f511874fd89ed8393f76663e434f2f8bb1dff7da3110771a199a0eb3e2b203189073e2fbedc63c1d2ff8e1d6820556b7e8548dbc9b59be04588c6ee41d41db36868581060723f4bc9d1857ddbb5c3e306ce97e54c102e48844f931', 'c2': '734aae69697f3c27bdba17ae8c3cc9903c4eb86bd095bf8cdc7c1a5d714c012ce69a0ab734f9d3e11f262f083ac7d92c4dd730c71c411bed568edf722a2c70e8d6173ec962214b2cd42e8408d99d22bccf99bdbcef27fe53387c3ed82f7ad2f89126ba4a3b015dd00168a5ba30d8c6849badffe118edebb0a37a5536577b7d80'}}
{'encrypted_res': {'c1': '4ffb5c04d089eeebf471c630d6405146111a8f1de9834c8079bab9225c87a2e68d70aaea67a4c408e0bbb68debad734e4e4245a9a3baa3581f9e87579eb8f973dca4d6333da593e8efc860307502897ac9bc5133130fe76f340e67efb79c20476c5fab621b1ae66158517a0c4ede49f37c0f88e03c9336ff627babf7996f5842', 'c2': '7b0c6d4ccc8de52ea0a21d0c130b345845a2d1fa1fdce23aa3450dc7dc1031294333acf59fa2f58199f86307e101c8c765a6c58c208ec781d4b33115876d60b5519d89c14fd0d509b0b0c2c37b18a9973f17b3c52bf90eb303b2cb68b90d767128edb25eec964a0ba5cb1197b69cf32452cec68b79c09aa089fc4c4e5cb349b1'}}

nc aclabs.ethz.ch 50901 


There are some subtle, but essential, differences between the ElGamal description you saw in the lecture and the one in the original paper. Feel free to reflect on them, but they are not important in the scope of this challenge or challenge M2.


In the lecture, your ElGamal public keys always have 4 components: p, q, g and y. Note that in this lab, q is always omitted: PyCryptodome always picks p, q such that q = (p-1)/2.
"""

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

PORT = 50901

loco = 1

host = "aclabs.ethz.ch"
if loco:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def main():
    r_pub = snd_rcv({"command": "get_public_key"})
    print(r_pub)
    p_B = int(r_pub["p"])
    g_B = int(r_pub["g"])
    y_B = int(r_pub["y"])
    
    key = ElGamal.generate(256, Random.new().read)

    B_pubkey = ElGamal.construct((p_B, g_B, y_B))
    
    r_set = snd_rcv({"command": "set_response_key", "p": int(key.p), "g": int(key.g), "y": int(key.y)})

    print(r_set)

    c1, c2 = ElGamalImpl.encrypt(B_pubkey, b"backdoor")

    r_flag = snd_rcv({"command": "encrypted_command", "encrypted_command": {"c1": c1.hex(), "c2": c2.hex()}})
    c1 = bytes.fromhex(r_flag["encrypted_res"]["c1"])
    c2 = bytes.fromhex(r_flag["encrypted_res"]["c2"])
    flag = ElGamalImpl.decrypt(key, c1, c2)

    print(flag)

if __name__ == "__main__":
    main()
