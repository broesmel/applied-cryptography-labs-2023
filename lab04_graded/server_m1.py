import json
import hashlib
import os
import secrets
import time
from boilerplate import CommandServer, on_command

from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES


class CoffeeMachine(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.current_user = None
        self.good_coffee = False

        key = secrets.token_bytes(16)
        self.cipher = AES.new(key, AES.MODE_ECB)

        super().__init__(*args, **kwargs)

    @on_command("register")
    def handle_register(self, msg):
        """This method allows you to register a new (non-admin) account, receiving a login token in the end"""

        try:
            username = msg["username"]
            favourite_coffee = msg["favourite_coffee"]

            # Sorry, new users cannot be admin. Call our customer support for complaints.
            token = "&".join(
                [
                    f"username={username}",
                    "role=user",
                    f"favourite_coffee={favourite_coffee}",
                ]
            )

            # In our innovative passwordless design, the user logs in using an encrypted token.
            # Since we're the only one that can encrypt it, this ensures that the user cannot forge a new token.
            ctxt = self.cipher.encrypt(pad(token.encode(), self.cipher.block_size))

            self.send_message({"token": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("login")
    def handle_login(self, msg):
        """This method allows you to login, provided that you have registered before"""

        if self.current_user is not None:
            self.send_message({"error": "Log out first!"})
            return

        try:
            token_enc = bytes.fromhex(msg["token"])
            token_str = unpad(
                self.cipher.decrypt(token_enc), self.cipher.block_size
            ).decode()

            entries = token_str.split("&")
            user = {}
            for entry in entries:
                key, val = entry.split("=")
                if key in user:
                    # Skip duplicated entries... you never know
                    continue
                user[key] = val

            if (
                "username" not in user
                or "role" not in user
                or "favourite_coffee" not in user
            ):
                self.send_message({"error": "Malformed token"})
                return

            self.current_user = user
            self.send_message(
                {
                    "res": f"Hello {user['username']}, welcome to the AC lab coffee machine! Your role is: {user['role']}."
                }
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("change_settings")
    def handle_change_settings(self, msg):
        if self.current_user is None:
            self.send_message({"error": "Log in first!"})
            return

        if self.current_user["role"] != "admin":
            self.send_message({"error": "Only admins can change settings"})
            return

        try:
            good_coffee = msg["good_coffee"]
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

        if good_coffee == "true":
            self.good_coffee = True

        self.send_message(
            {
                "res": f"Hi {self.current_user['username']}, we changed the settings for you!"
            }
        )

    @on_command("get_coffee")
    def handle_get_coffee(self, msg):
        if self.good_coffee:
            self.send_message(
                {
                    "res": f"Mhhh, that's some good stuff... Here is a flag to go alongside it: {self.flag}"
                }
            )
        else:
            self.send_message({"res": "Watery, cold, acid... enjoy your coffee..."})

    @on_command("logout")
    def handle_logout(self, msg):
        if self.current_user is None:
            self.send_message({"res": "You are already logged out."})
        else:
            self.send_message({"res": "You have been logged out. Bis bald!"})
            self.current_user = None


if __name__ == "__main__":
    flag = "flag{test_flag}"
    CoffeeMachine.start_server("0.0.0.0", 50401, flag=flag)
