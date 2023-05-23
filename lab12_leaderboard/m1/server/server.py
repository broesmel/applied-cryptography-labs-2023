#!/usr/bin/env python3
from boilerplate import CommandServer, on_command, on_startup

import time
import json

from Crypto.Hash import SHA256
from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

CURVE_NAME = "secp256r1"
CURVE_P_LEN = 32


def point_to_bytes(point: ECC.EccPoint):
    y = int(point.y).to_bytes(CURVE_P_LEN, "big")
    x = int(point.x).to_bytes(CURVE_P_LEN, "big")
    return x + y


def xor(X: bytes, Y: bytes):
    return bytes(x ^ y for (x, y) in zip(X, Y))


class OneTimeECDHEAKEServer(CommandServer):
    def __init__(self, flag: str, key: ECC.EccKey, *args, **kwargs):
        self.flag = flag

        self.server_long_term = key
        self.server_signer = DSS.new(self.server_long_term, "fips-186-3")

        self.client_id = None

        self.server_eph = None
        self.shared_key = None

        super().__init__(*args, **kwargs)

    @on_startup()
    def server_startup(self):
        self.server_eph = ECC.generate(curve=CURVE_NAME)

    @on_command("get_public_key")
    def get_public_key(self, msg):
        x = int(self.server_long_term.pointQ.x)
        y = int(self.server_long_term.pointQ.y)
        self.send_message(
            {
                "x": x,
                "y": y,
            }
        )

    @on_command("client_hello")
    def client_hello(self, msg):
        try:
            self.client_id = msg["id"]

            # check if point belongs to the curve
            client_eph_x = int(msg["eph_x"])
            client_eph_y = int(msg["eph_y"])
            client_eph = ECC.EccPoint(client_eph_x, client_eph_y, curve=CURVE_NAME)

            # If the client is another IoT server, authenticate it
            if self.client_id == "server":
                signature = bytes.fromhex(msg["signature"])
                chall = point_to_bytes(client_eph)
                h = SHA256.new(chall)
                self.server_signer.verify(h, signature)

            shared = self.server_eph.d * client_eph
            key_raw = point_to_bytes(shared)
            print(f"Shared key: {key_raw.hex()}")
            self.shared_key = HKDF(
                master=key_raw,
                salt=None,
                key_len=32,
                hashmod=SHA256,
                context=b"aead encryption",
            )

            transcript = point_to_bytes(client_eph) + point_to_bytes(self.server_eph.pointQ)
            h = SHA256.new(transcript)
            transcript_sign = self.server_signer.sign(h)

            eph_x = int(self.server_eph.pointQ.x)
            eph_y = int(self.server_eph.pointQ.y)
            # Reply with server hello
            self.send_message(
                {
                    "eph_x": eph_x,
                    "eph_y": eph_y,
                    "signature": transcript_sign.hex(),
                }
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"{type(e).__name__}: {e}"})

    def handle_encrypted_payload(self, enc_payload, tag, nonce):
        cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=nonce.to_bytes(8, "big"))
        payload = json.loads(cipher.decrypt_and_verify(enc_payload, tag).decode())

        match payload["secure_command"]:
            case "echo":
                res = bytes.fromhex(payload["echo"])
            case "time":
                res = time.ctime().encode()
            case "report":
                with open("log", "a") as f:
                    f.write(f"{self.client_id}: {payload['temperature']}\n")
                res = b"ok"
            case "read":
                print(f"Client {self.client_id} requested the flag")
                if self.client_id == "server":
                    with open("log", "r+b") as f:
                        res = f.read() + self.flag.encode()
                else:
                    res = b"this violation will be reported"
            case _:
                res = b"no such command"

        return res

    def encrypt_and_sign_response(self, res, nonce):
        cipher = AES.new(self.shared_key, AES.MODE_GCM, nonce=nonce.to_bytes(8, "big"))
        enc_res, tag = cipher.encrypt_and_digest(res)
        h = SHA256.new(enc_res)
        signature = self.server_signer.sign(h)
        return enc_res, tag, signature

    @on_command("secure_command")
    def secure_command(self, msg):
        if self.shared_key is None:
            self.send_message({"res": "Unexpected message!"})

        try:
            enc_payload = bytes.fromhex(msg["enc_payload"])
            tag = bytes.fromhex(msg["tag"])
            nonce = msg["nonce"]

            print(f"Received encrypted payload: {enc_payload.hex()}")
            print(f"Received tag: {tag.hex()}")
            print(f"Received nonce: {nonce}")


            res = self.handle_encrypted_payload(enc_payload, tag, nonce)

            print(f"Sending response: {res}")

            enc_res, tag, signature = self.encrypt_and_sign_response(res, nonce + 1)

            self.send_message(
                {
                    "enc_res": enc_res.hex(),
                    "tag": tag.hex(),
                    "signature": signature.hex(),
                }
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"{type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    key = ECC.generate(curve=CURVE_NAME)
    OneTimeECDHEAKEServer.start_server("0.0.0.0", 51201, flag=flag, key=key)
