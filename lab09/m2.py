#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.PublicKey import ElGamal
from Crypto import Random
from Crypto.Util.number import bytes_to_long, long_to_bytes

from elgamal import ElGamalImpl

"""
 M2: Attacking an ElGamal IoT Carpet
100
interactive

    Only 4 hours left before the launch! The marketing team decided that the IoT Carpet will ship with the Aladdin Cloud TM -- for enhanced control and security, the public key of the Carpet is now hidden!

    The commands will only be encrypted by our cloud, so user can enjoy vendor lock-in... I mean state-of-the-art cloud controls!

You no longer have the public key of the Carpet -- hence you can't simply issue commands to the Carpet anymore.

You will find the ElGamal parameters of the Carpet in the response of the command get_public_parameters.

Mount an attack and retrieve the flag.

Note: To run the server locally, use your ElGamal implementation from challenge M1.
nc aclabs.ethz.ch 50902 
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

PORT = 50902

loco = 0

host = "aclabs.ethz.ch"
if loco:
    host = "localhost"

tn = telnetlib.Telnet(host, PORT)

def main():
    # key = ElGamal.generate(256, Random.new().read)

    p = 159326835256483747648683076552682480331934665910988420126125732402886077697040405547527521052897522971639414942528584820613412700564266171035566397568340970436590658287081846532208510854817985267864719388059404226126504848548282569940069730875333836687798954359620574875378036236852092341101685569338013749763
    g = 150988509186006229012634482071480382735449339154979059535519938500904353232673070656631345315464282941110540904488251642513304425357449197751364751848365122613530810708258187291141210645471300804655435331215972818402518171327475917779224923635112870077847351127800902471675259673445273165189869519993489513141
    y = 81031794553590424746805781583782590804952656371985350721984600080078536983496464284475718059229163152986451870054746269473117218771763388681221118924918938194763797451851120953721150647503975829226719008651941292632830009249992062005592663114980777782674598027011233125508037873137612002496382949433960370978
    x = 40230525246845515396879425357478057082343481758084701839686386301099139466834105175935399204235110685076486575306483891146707489513646682351652071953683716849353698690476041058648653225806163618699277166876237570666284332302766981309757140653555899524639357725790626210484312349331840047444976726304723293903
    key = ElGamal.construct((p, g, y, x))

    r_pub = snd_rcv({"command": "get_public_parameters"})
    print(r_pub)
    p_B = int(r_pub["p"])
    g_B = int(r_pub["g"])
    
    
    # B_pubkey = ElGamal.construct((p, g, y))

    r_set = snd_rcv({"command": "set_response_key", "p": int(key.p), "g": int(key.g), "y": int(key.y)})

    print(r_set)

    r_garb = snd_rcv({"command": "encrypted_command", "encrypted_command": {"c1": bytes([1]).hex(), "c2": b'backdoor'.hex()}})
    c1 = bytes.fromhex(r_garb["encrypted_res"]["c1"])
    c2 = bytes.fromhex(r_garb["encrypted_res"]["c2"])

    print(ElGamalImpl.decrypt(key, c1, c2))

if __name__ == "__main__":
    main()
