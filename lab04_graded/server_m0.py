import secrets
import os
import time
import json
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Cipher import AES
from Crypto.Hash import SHA256

# Two minutes to reach the target score
TIMEOUT_SECONDS = 120
TARGET = 64


class PRFServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.memory = {}
        self.generated = set()
        self.key = b""
        self.bit = 0
        self.score = 0

        # Set up the timer countdown
        self.start = time.time()

        super().__init__(*args, **kwargs)

    def handle_timeout(self):
        """This function is called when the timer finishes"""
        self.send_message({"error": "Sorry, you took too long!"})
        self.close_connection()

    def encrypt(self, msg: bytes):
        lkey = SHA256.new(self.key[:2]).digest()
        rkey = SHA256.new(self.key[2:]).digest()

        lcipher = AES.new(lkey, AES.MODE_ECB)
        rcipher = AES.new(rkey, AES.MODE_ECB)

        ctxt = lcipher.encrypt(msg)
        return rcipher.encrypt(ctxt)

    @on_startup()
    def initialize_new_round(self):
        self.key = secrets.token_bytes(4)
        self.bit = secrets.randbits(1)
        self.memory = {}
        self.generated = set()

    @on_command("query")
    def handle_query(self, msg):
        """This method implements the real-or-random oracle for the PRF game"""

        try:
            m = bytes.fromhex(msg["m"])
            if len(m) != 16:
                self.send_message(
                    {"error": f"Sorry, we don't support messages of this length!"}
                )
                return

            if self.bit == 0:
                ctxt = self.encrypt(m)
            elif self.bit == 1:
                if m in self.memory:
                    ctxt = self.memory[m]
                else:
                    # Lazy evaluation of a random permutation
                    while True:
                        ctxt = secrets.token_bytes(16)
                        if ctxt not in self.generated:
                            self.memory[m] = ctxt
                            self.generated.add(ctxt)
                            break

            self.send_message({"res": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("guess")
    def handle_guess(self, msg):
        """Call this method when you are ready to guess the challenge bit `b`"""

        if time.time() - self.start > TIMEOUT_SECONDS:
            self.handle_timeout()
            return

        try:
            b = int(msg["b"])
            if b == self.bit:
                self.score += 1
                self.initialize_new_round()
                self.send_message({"res": f"Good! ({self.score}/{TARGET})"})
            else:
                self.send_message({"res": "This ain't it chief."})
                self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        if self.score >= TARGET:
            self.send_message({"flag": self.flag})
            return

        self.send_message({"res": "Not enough correct guesses!"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    PRFServer.start_server("0.0.0.0", 50400, flag=flag)
