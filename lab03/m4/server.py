#!/usr/bin/env python3
import secrets

from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


class PaddingOracle(CommandServer):
    """PaddingOracle implements a padding-error guessing challenger.

    The challenger interacts with an adversary, and reveals a flag to the
    adversary if they show a significant advantage in the padding-error guessing game.
    """

    def __init__(self, key, flag, *args, **kwargs):
        self.flag = flag
        self.rounds = 300
        self.guesses = 0

        self.block_size = 16
        self.k = key

        self.ctxt_db = {}
        self.padding_error = None

        super().__init__(*args, **kwargs)

    def ctxt_check(self, ctxt: bytes, check: bool = True):
        """Prevent trivial wins by reflecting the responses as commands, or by
        sending the same ciphertext multiple times.

        Store every block of the input ciphertext.  If check is true, and a
        block of ciphertext was already seen, raise an exception.
        """
        ctxt_blocks = [
            ctxt[i : i + self.block_size] for i in range(0, len(ctxt), self.block_size)
        ]
        if check and any(self.ctxt_db.get(ctxt_block) for ctxt_block in ctxt_blocks):
            raise ValueError("You cannot just reflect or repeat ct blocks.")

        for ctxt_block in ctxt_blocks:
            self.ctxt_db[ctxt_block] = True

    def send_encrypted_message(self, msg):
        cipher = AES.new(self.k, AES.MODE_CBC)
        ctxt = cipher.encrypt(pad(msg.encode(), self.block_size))
        encrypted_res = cipher.iv + ctxt
        self.ctxt_check(encrypted_res, False)
        self.send_message({"res": encrypted_res.hex()})

    @on_command("decrypt")
    def decrypt_handler(self, msg):
        try:
            ciphertext = bytes.fromhex(msg["ciphertext"])
            self.ctxt_check(ciphertext)
            iv = ciphertext[: self.block_size]
            ctxt = ciphertext[self.block_size :]

            cipher = AES.new(self.k, AES.MODE_CBC, iv=iv)
            ptxt = cipher.decrypt(ctxt)
            self.padding_error = False
            try:
                plaintext = unpad(ptxt, self.block_size)
            except ValueError as e:
                self.padding_error = True
                raise e

            plaintext = plaintext.decode()

            self.send_encrypted_message("Hello!")
        except (KeyError, ValueError) as e:
            self.send_encrypted_message(repr(e))

    @on_command("guess")
    def guess_handler(self, msg):
        if "guess" not in msg:
            self.send_message({"res": "A guess is required."})
            return
        padding_error_guess = msg["guess"]

        if self.padding_error != padding_error_guess or self.padding_error is None:
            self.send_message({"res": "You lost"})
            self.close_connection()
            return

        self.guesses += 1
        self.send_message({"res": f"You won round {self.guesses}/{self.rounds}!"})
        self.padding_error = None

    @on_command("flag")
    def flag_handler(self, msg):
        if self.guesses < self.rounds:
            self.send_message({"res": "Not enough guesses!"})
            self.close_connection()
            return

        self.send_message({"res": self.flag})
        self.close_connection()


if __name__ == "__main__":
    key = secrets.token_bytes(16)
    flag = "flag{test_flag}"
    PaddingOracle.start_server("localhost", 50340, key=key, flag=flag)
