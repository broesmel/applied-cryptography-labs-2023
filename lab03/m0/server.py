#!/usr/bin/env python3
import secrets

from boilerplate import CommandServer, Message, on_command

from strangectr import StrangeCTR


class StrangeCTROracle(CommandServer):
    """This server accepts encrypted commands, encrypted with StrangeCTR."""

    def __init__(self, key: bytes, nonce: bytes, flag: str, *args, **kwargs):
        self.key = key
        self.nonce = nonce
        self.flag = flag
        self.cipher = StrangeCTR(self.key, nonce=self.nonce, initial_value=0)
        super().__init__(*args, **kwargs)

    @on_command("howto")
    def handle_intro(self, msg: Message):
        cipher = StrangeCTR(self.key, nonce=self.nonce, initial_value=0)
        encrypted_intro = cipher.encrypt(b"intro")
        self.send_message({
            "res": "Welcome! To use encrypted commands, send: " +
            "{'command': 'encrypted_command', 'encrypted_command': '...ciphertext here...'}. " +
            f"Here's an encryption of the 'intro' command to get you started: {encrypted_intro.hex()}"
        })

    @on_command("encrypted_command")
    def encrypted_command_handler(self, msg: Message):
        if "encrypted_command" not in msg:
            self.send_message({"res": "The encrypted command is required."})
            return
        encrypted_command = msg["encrypted_command"]

        try:
            command = self.cipher.decrypt(bytes.fromhex(encrypted_command))
        except (ValueError) as _:
            self.send_message({"res": "Failed to execute command: Decryption failed"})
            return

        match command:
            case b"intro":
                self.intro_handler()
            case b"flag":
                self.flag_handler()
            case _:
                self.send_message({"res": "No such command: " + command.hex()})

    def intro_handler(self):
        self.send_message(
            {"res": 'Welcome to the oracle! The "flag" command will give you the flag!'}
        )

    def flag_handler(self):
        self.send_message({"res": self.flag})


if __name__ == "__main__":
    key = secrets.token_bytes(16)
    nonce = secrets.token_bytes(8)
    flag = "flag{test_flag}"

    StrangeCTROracle.start_server("localhost", 50301, key=key, nonce=nonce, flag=flag)
