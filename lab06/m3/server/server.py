#!/usr/bin/env python3
import secrets

from string import ascii_letters, digits

from boilerplate import CommandServer, on_command, on_startup

from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

ALPHABET = ascii_letters + digits


class EncryptAndMacOracle(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag

        self.guesses = 0
        self.rounds = 128
        self.message = None
        self.message_ctxt = None

        # KeyGen
        self.key = secrets.token_bytes(16)
        self.k_auth = HKDF(
            master=self.key,
            salt=None,
            key_len=16,
            hashmod=SHA256,
            context=b"authentication",
        )
        self.k_enc = HKDF(
            master=self.key,
            salt=None,
            key_len=16,
            hashmod=SHA256,
            context=b"encryption",
        )

        super().__init__(*args, **kwargs)

    @on_startup()
    def generate_secret_string(self):
        message_len = 4
        self.message = "".join(secrets.choice(ALPHABET) for _ in range(message_len))
        self.message_ctxt = self.encrypt_and_mac(self.message.encode())

    def encrypt_and_mac(self, ptxt):
        # encrypt
        cipher = AES.new(self.k_enc, AES.MODE_CBC)
        ctxt = cipher.encrypt(pad(ptxt, AES.block_size))
        iv = cipher.iv

        # mac
        tag = HMAC.new(self.k_auth, ptxt, SHA256).digest()

        return iv + ctxt + tag

    @on_command("challenge")
    def challenge_handler(self, msg):
        self.send_message({"res": self.message_ctxt.hex()})

    @on_command("corrupt")
    def corrupt_handler(self, msg):
        self.send_message(
            {
                "res": "We are very generous, here is the authentication key: "
                + self.k_auth.hex()
            }
        )

    @on_command("guess")
    def guess_handler(self, msg):
        try:
            guess = msg["guess"]
            if guess == self.message:
                self.guesses += 1
                self.send_message(
                    {"res": f"You won round {self.guesses}/{self.rounds}!"}
                )
            else:
                self.send_message({"res": "Nope."})
                self.close_connection()

            self.generate_secret_string()
        except (KeyError, ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

    @on_command("flag")
    def flag_handler(self, msg):
        if self.guesses < self.rounds:
            self.send_message({"res": "Not enough guesses!"})
            return

        self.send_message({"res": self.flag})
        self.close_connection()


if __name__ == "__main__":
    flag = "flag{test_flag}"
    EncryptAndMacOracle.start_server("0.0.0.0", 50603, flag=flag)
