#!/usr/bin/env python3
import secrets 
import json

from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto.Cipher import AES

from boilerplate import CommandServer, on_command

# this is what you implemented in the lab, do assume it is IND-CCA secure
from aead import CBC_HMAC

class ControlPanel(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.users = {
            "normal": [b"admin", b"controller"],
            "restricted": [b"guest"]
        }
        self.flag = flag
        self.state = "What a beautiful dream, That could flash on the screen"

        self.key = secrets.token_bytes(56)
        self.aead = CBC_HMAC(32, 24, self.key)

        self.auth = 0
        super().__init__(*args, **kwargs)

    @on_command("get_token")
    def get_token(self, msg):
        """Get the guest token"""
        guest_token = self.aead.encrypt(b'guest').hex()
        self.send_message({"resp":"ok","guest token": guest_token})

    def is_restricted(self, user: str):
        if user in self.users["restricted"]:
            return True
        return False

    @on_command("authenticate")
    def authenticate(self, msg):
        """Authenticate to the server with a token"""
        try:
            token = bytes.fromhex(msg["token"])
            user = self.aead.decrypt(token)
            if not self.is_restricted(user):
                self.auth = 2
            else:
                self.auth = 1
            self.send_message({"resp":"ok"})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("show_state")
    def show_state(self, msg):
        """Fetch the state"""
        try:
            prefix = bytes.fromhex(msg["prefix"])
            if self.auth == 1:
                self.send_message({"resp": prefix.decode() + self.state})
            if self.auth == 2:
                self.send_message({"resp": prefix.decode() + self.state +  "\n" + self.flag})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("rekey")
    def rekey(self, msg):
        """Modify the key"""
        try:
            key = bytes.fromhex(msg["key"])
            self.key = bytes([key[i] ^ self.key[i] for i in range(len(self.key))])
            self.aead = CBC_HMAC(32, 24, self.key)
            self.send_message({"resp": "ok"})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag_1}"
    ControlPanel.start_server("0.0.0.0", 50707, flag=flag)
