#!/usr/bin/env python3
import secrets

from boilerplate import CommandServer, on_command
from passlib.hash import argon2


class ArgonServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.password = secrets.token_bytes(32)
        self.flag = flag
        super().__init__(*args, **kwargs)

    @on_command("guess")
    def guess_handler(self, msg):
        try:
            guess = msg["guess"]
            if argon2.verify(self.password, guess):
                self.send_message({"res": self.flag})
            else:
                self.send_message({"res": "Invalid password"})
        except Exception as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

    @on_command("password")
    def password_handler(self, msg):
        self.send_message({"res": self.password.hex()})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    ArgonServer.start_server("0.0.0.0", 50501, flag=flag)
