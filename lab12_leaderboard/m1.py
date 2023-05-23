#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json
from Crypto.Util.number import bytes_to_long, long_to_bytes, getRandomInteger

# from the server

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


import secrets

"""
 M1: Reflecting on Authenticated Key Exchange
100 
    We just secured our IoT sensor network! Now the client nodes can securely report the temperature to the servers, and only authenticated servers can access the temperature logs!

This AKE is just like the one in the lectures! Ephemeral Diffie-Hellman, AES-GCM, secure parameters... Kenny would be proud of us!
nc aclabs.ethz.ch 51201 
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
PORT = 51201
loco = 0
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)
    

# from the server code
CURVE_NAME = "secp256r1"
CURVE_P_LEN = 32
def point_to_bytes(point: ECC.EccPoint):
    y = int(point.y).to_bytes(CURVE_P_LEN, "big")
    x = int(point.x).to_bytes(CURVE_P_LEN, "big")
    return x + y

def main():
    # Generate a random private key
    client_eph = ECC.generate(curve=CURVE_NAME)
    public_key = client_eph.public_key()

    # Step 1: Request public key from the server
    server_public_key = snd_rcv({"command": "get_public_key"})

    # Step 3: Send client hello with client's ephemeral public key
    client_hello_msg = {
        "command": "client_hello",
        "id": "client",
        "eph_x": int(client_eph.pointQ.x),
        "eph_y": int(client_eph.pointQ.y),
    }

    server_hello_msg = snd_rcv(client_hello_msg)
    # Step 4: Receive server hello with server's ephemeral public key
    server_eph_x = server_hello_msg["eph_x"]
    server_eph_y = server_hello_msg["eph_y"]
    server_eph = ECC.EccPoint(server_eph_x, server_eph_y, curve=CURVE_NAME)

    # Step 5: Perform key agreement
    shared_secret = client_eph.d * server_eph
    key_raw = point_to_bytes(shared_secret)

    print(f"Shared key: {key_raw.hex()}")

    # Step 6: Derive encryption key using HKDF
    shared_key = HKDF(
        master=key_raw,
        salt=None,
        key_len=32,
        hashmod=SHA256,
        context=b"aead encryption",
    )

    # Step 7: Encrypt and sign the payload
    chall_dec = point_to_bytes(client_eph.pointQ)
    payload = {"secure_command": "echo", "echo": chall_dec.hex()}
    nonce = 0
    enc_payload = AES.new(shared_key, AES.MODE_GCM, nonce=nonce.to_bytes(8, "big"))
    enc_payload_data, tag = enc_payload.encrypt_and_digest(json.dumps(payload).encode())

    # Step 8: Send the secure command with the encrypted payload
    secure_command_msg = {
        "command": "secure_command",
        "enc_payload": enc_payload_data.hex(),
        "tag": tag.hex(),
        "nonce": nonce,
    }
    r_secure_command_msg = snd_rcv(secure_command_msg)

    print(r_secure_command_msg)

    # Step 9: Process the r_secure_command_msg
    enc_res = bytes.fromhex(r_secure_command_msg["enc_res"])
    tag = bytes.fromhex(r_secure_command_msg["tag"])
    signature = bytes.fromhex(r_secure_command_msg["signature"])
    cipher = AES.new(shared_key, AES.MODE_GCM, nonce=(nonce + 1).to_bytes(8, "big"))
    decrypted_response = cipher.decrypt_and_verify(enc_res, tag)
    print(f"{decrypted_response=}")
    
    # get signature for the chall
    chall = enc_res
    payload = {"secure_command": "echo", "echo": chall.hex()}
    nonce = 0
    enc_payload = AES.new(shared_key, AES.MODE_GCM, nonce=nonce.to_bytes(8, "big"))
    enc_payload_data, tag = enc_payload.encrypt_and_digest(json.dumps(payload).encode())

    # Step 8: Send the secure command with the encrypted payload
    secure_command_msg = {
        "command": "secure_command",
        "enc_payload": enc_payload_data.hex(),
        "tag": tag.hex(),
        "nonce": nonce,
    }
    r_secure_command_msg = snd_rcv(secure_command_msg)
    print(r_secure_command_msg)
    signature = bytes.fromhex(r_secure_command_msg["signature"])

    # Step 10: ask for server-server hello
    server_server_hello_msg = {
        "command": "client_hello",
        "id": "server",
        "eph_x": int(client_eph.pointQ.x),
        "eph_y": int(client_eph.pointQ.y),
        "signature": signature.hex(),
    }
    r_server_server_hello_msg = snd_rcv(server_server_hello_msg)
    print(r_server_server_hello_msg)


    # get flag
    payload = {"secure_command": "read"}
    nonce = 0
    enc_payload = AES.new(shared_key, AES.MODE_GCM, nonce=nonce.to_bytes(8, "big"))
    enc_payload_data, tag = enc_payload.encrypt_and_digest(json.dumps(payload).encode())

    # Step 8: Send the secure command with the encrypted payload
    secure_command_msg = {
        "command": "secure_command",
        "enc_payload": enc_payload_data.hex(),
        "tag": tag.hex(),
        "nonce": nonce,
    }
    r_secure_command_msg = snd_rcv(secure_command_msg)
    print(r_secure_command_msg)

    # Step 9: Process the r_secure_command_msg
    enc_res = bytes.fromhex(r_secure_command_msg["enc_res"])
    tag = bytes.fromhex(r_secure_command_msg["tag"])
    signature = bytes.fromhex(r_secure_command_msg["signature"])
    cipher = AES.new(shared_key, AES.MODE_GCM, nonce=(nonce + 1).to_bytes(8, "big"))
    decrypted_response = cipher.decrypt_and_verify(enc_res, tag)
    print(f"{decrypted_response=}")
    

if __name__ == "__main__":
    main()


