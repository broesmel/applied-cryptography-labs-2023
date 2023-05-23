#!/usr/bin/env python3
import secrets

from boilerplate import CommandServer, Message, on_command
from strangecbc import StrangeCBC


class StrangeCBCOracle(CommandServer):
    """This server runs the strangeCBC cipher. It accepts encrypted commands"""

    def __init__(self, key: bytes, flag: str, *args, **kwargs):
        self.key = key
        self.flag = flag
        super().__init__(*args, **kwargs)

    @on_command("howto")
    def handle_howto(self, msg: Message):
        cipher = StrangeCBC(self.key)
        encrypted_intro = cipher.iv + cipher.encrypt(b"intro")
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

        block_size = 16
        encrypted_command = bytes.fromhex(msg["encrypted_command"])
        iv, ctxt = encrypted_command[:block_size], encrypted_command[block_size:]
        cipher = StrangeCBC(self.key, iv=iv)

        try:
            command = cipher.decrypt(ctxt)
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
    flag = "flag{test_flag}"

    StrangeCBCOracle.start_server("localhost", 50303, key=key, flag=flag)
