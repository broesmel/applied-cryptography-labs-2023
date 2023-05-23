#!/usr/bin/env python3
import secrets

from boilerplate import CommandServer, Message, on_command

from strangectr import StrangeCTR


class StrangeCTROracle(CommandServer):
    """This server accepts encrypted commands, encrypted with StrangeCTR."""

    def __init__(self, key: bytes, flag: str, *args, **kwargs):
        self.key = key
        self.flag = flag
        self.cipher = StrangeCTR(self.key)
        super().__init__(*args, **kwargs)

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
    flag = "flag{test_flag}"

    StrangeCTROracle.start_server("localhost", 50302, key=key, flag=flag)
