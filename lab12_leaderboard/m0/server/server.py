#!/usr/bin/env python3
import secrets

from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import long_to_bytes
from Crypto.Cipher import AES
from Crypto.Hash import SHA512

from boilerplate import CommandServer, on_command


# Secure Diffie Hellamn parameters. Large prime p and a generator g of the group.
p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
q = (p - 1) // 2
g = 3


class SecureKeyExchange(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag

        # Bosses private and public key.
        self.boss_private = secrets.randbelow(q - 1) + 1
        self.boss_public = pow(g, self.boss_private, p)
        self.boss_storage = {"nonce": None, "client_nonce": None}

        # Clients use this fingerprint to authenticate the Boss.
        self.client_storage = {
            "nonce": None,
            "boss_nonce": None,
            "boss_fingerprint": SHA512.new(
                self.boss_public.to_bytes(p.bit_length() // 8 + 1, "big")
            ).digest(),
        }

        # To store the state of the session
        self.boss_compromised = False
        self.client_initalised = False

        super().__init__(*args, **kwargs)

    @on_command("client_hello")
    def client_hello(self, msg):
        try:
            if self.client_initalised:
                raise ValueError("Already initialized")

            if self.boss_compromised:
                raise ValueError("Illegal flow")

            nonce = secrets.token_bytes(16)
            self.client_storage["nonce"] = nonce
            self.send_message(
                {
                    "res": "Hi, let's talk!",
                    "client_nonce": nonce.hex(),
                }
            )
            self.client_initalised = True
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"{type(e).__name__}: {e}"})

    @on_command("boss_hello")
    def boss_hello(self, msg):
        try:
            self.boss_storage["client_nonce"] = bytes.fromhex(msg["client_nonce"])

            nonce = secrets.token_bytes(16)
            self.boss_storage["nonce"] = nonce
            self.send_message(
                {
                    "res": "Hello there! Here is my public key",
                    "pubkey": self.boss_public,
                    "boss_nonce": nonce.hex(),
                }
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"{type(e).__name__}: {e}"})

    @on_command("client_finished")
    def client_finished(self, msg):
        try:
            if self.boss_compromised:
                raise ValueError("Illegal flow")

            if not self.client_initalised:
                raise ValueError("Illegal flow")

            self.client_storage["boss_nonce"] = bytes.fromhex(msg["boss_nonce"])
            public_key = msg["pubkey"]

            # Check if the received key matches the locally stored fingerprint.
            if (
                SHA512.new(public_key.to_bytes(p.bit_length() // 8 + 1, "big")).digest()
                != self.client_storage["boss_fingerprint"]
            ):
                raise ValueError("Tampering detected")

            shared_secret = secrets.randbelow(p)
            # Encrypt the shared key using ElGamal.
            eph_private = secrets.randbelow(q - 1) + 1
            eph_public = pow(public_key, eph_private, p)
            c_1 = pow(g, eph_private, p)
            c_2 = (eph_public * shared_secret) % p

            secure_key = HKDF(
                master=long_to_bytes(shared_secret),
                key_len=32,
                salt=self.client_storage["nonce"] + self.client_storage["boss_nonce"],
                hashmod=SHA512,
                num_keys=1,
            )
            cipher = AES.new(secure_key, AES.MODE_CTR)

            secret_message = f"Hi boss! This is the very important message I was telling you about {self.flag}. Please make sure not to share this with anyone! It's of the utmost importance."
            ciphertext = cipher.encrypt(secret_message.encode())
            self.send_message(
                {
                    "resp": "ok",
                    "encrypted_shared_key": {"c1": c_1, "c2": c_2},
                    "ciphertext": ciphertext.hex(),
                    "nonce": cipher.nonce.hex(),
                }
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"{type(e).__name__}: {e}"})

    @on_command("boss_finished")
    def boss_finished(self, msg):
        try:
            # First do ElGamal Decryption to get the shared secret
            c_1 = msg["encrypted_shared_key"]["c1"]
            c_2 = msg["encrypted_shared_key"]["c2"]
            K = pow(c_1, self.boss_private, p)
            shared_secret = (c_2 * pow(K, -1, p)) % p

            secure_key = HKDF(
                master=long_to_bytes(shared_secret),
                key_len=32,
                salt=self.boss_storage["client_nonce"] + self.boss_storage["nonce"],
                hashmod=SHA512,
                num_keys=1,
            )
            cipher = AES.new(
                secure_key, AES.MODE_CTR, nonce=bytes.fromhex(msg["nonce"])
            )
            message = cipher.decrypt(bytes.fromhex(msg["ciphertext"]))
            self.send_message(
                {"res": "Thank you for delivering the very important message to me!"}
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"{type(e).__name__}: {e}"})

    @on_command("compromise")
    def compromise(self, msg):
        """Compromise the Boss, revaling his secret key. Note that after this the client will no longer communicate with the boss"""
        self.boss_compromised = True
        self.send_message({"res": "Success", "secret": self.boss_private})


if __name__ == "__main__":
    flag = "flag{test_flag_1}"
    SecureKeyExchange.start_server("0.0.0.0", 51200, flag=flag)
