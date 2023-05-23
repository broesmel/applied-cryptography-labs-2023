#!/usr/bin/env python3
import secrets
import time

from boilerplate import CommandServer, on_command, on_startup

from Crypto.Hash import HMAC, SHA256

TIMEOUT_SECONDS = 2


class PasswordServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.salt = secrets.token_bytes(16)
        self.flag = flag

        self.guesses = 0
        self.rounds = 5
        self.start = None
        self.password = None

        super().__init__(*args, **kwargs)

    @on_command("salt")
    def salt_handler(self, msg):
        """Call this to get the random salt used by the server"""
        self.send_message({"salt": self.salt.hex()})

    @on_command("guess")
    def guess_handler(self, msg):
        """Call this when you are ready to make a guess"""
        if self.start is None or self.password is None:
            self.send_message(
                {
                    "res": "You first need to send the password command, to make the server generate a password"
                }
            )
            return

        if time.time() - self.start > TIMEOUT_SECONDS:
            self.send_message({"error": "Sorry, you took too long!"})
            self.close_connection()
            return

        try:
            password = msg["password"]
            if password == self.password.decode():
                self.guesses += 1
                self.password = None
                self.send_message(
                    {"res": f"You won round {self.guesses}/{self.rounds}!"}
                )
            else:
                self.send_message({"res": "This ain't it chief."})

        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("password")
    def password_handler(self, msg):
        """Make the server generate a password, and send the hashed version of it"""
        if self.password is not None:
            self.send_message(
                {
                    "error": "Sorry, you can't change password without a on-time correct guess for the previous one."
                }
            )
            self.close_connection()
            return

        pw = bytes(secrets.choice(range(ord("a"), ord("z"))) for _ in range(5))
        hsh = HMAC.new(self.salt, msg=pw, digestmod=SHA256).hexdigest()
        self.send_message({"pw_hash": hsh})
        self.start = time.time()
        self.password = pw

    @on_command("flag")
    def flag_handler(self, msg):
        if self.guesses < self.rounds:
            self.send_message({"error": "Not enough guesses!"})
            self.close_connection()
            return

        self.send_message({"flag": self.flag})
        self.close_connection()


if __name__ == "__main__":
    flag = "flag{test_flag}"
    PasswordServer.start_server("0.0.0.0", 50504, flag=flag)
