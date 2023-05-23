#!/usr/bin/env python3
import secrets
from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Hash import MD5


class StrangeAuthenticationServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.current_user = None

        self.key = secrets.token_bytes(16)

        super().__init__(*args, **kwargs)

    @on_command("token")
    def token_handler(self, msg):
        """Get an authentication token for our admin user, use it to login"""
        m1 = b"Pepper and lemon spaghetti with basil and pine nuts"
        recipe = b"Heat the oil in a large non-stick frying pan. Add the pepper and cook for 5 mins. Meanwhile, cook the pasta for 10-12 mins until tender. Add the courgette and garlic to the pepper and cook, stirring very frequently, for 10-15 mins until the courgette is really soft. Stir in the lemon zest and juice, basil and spaghetti (reserve some pasta water) and toss together, adding a little of the pasta water until nicely coated. Add the pine nuts, then spoon into bowls and serve topped with the parmesan, if using. Taken from [www.bbcgoodfood.com/recipes/pepper-lemon-spaghetti-basil-pine-nuts]"
        token = b"username:admin&m1:" + m1 + b"&fav_food_recipe:" + recipe
        cipher = AES.new(self.key, AES.MODE_CTR)
        token_enc = cipher.encrypt(token)
        nonce = cipher.nonce
        self.send_message({"nonce": nonce.hex(), "token_enc": token_enc.hex()})

    @on_command("login")
    def login_handler(self, msg):
        """This method allows you to login as our admin user"""

        if self.current_user is not None:
            self.send_message({"res": "Log out first!"})
            return

        try:
            token_enc = bytes.fromhex(msg["token_enc"])
            nonce = bytes.fromhex(msg["nonce"])
            cipher = AES.new(self.key, AES.MODE_CTR, nonce=nonce)
            token = cipher.decrypt(token_enc)

            entries = token.split(b"&")
            user = {}
            for entry in entries:
                key, val = entry.split(b":")
                user[key] = val

            if (
                b"username" not in user
                or b"m1" not in user
                or b"fav_food_recipe" not in user
            ) and len(user.keys()) != 3:
                self.send_message({"error": "Malformed token"})
                return

            m1 = user[b"m1"]
            h1 = MD5.new(m1).digest()
            m2 = bytes.fromhex(msg["m2"])
            h2 = MD5.new(m2).digest()
            if h1 == h2 and m1 != m2 and user[b"username"] == b"admin":
                self.current_user = user
                self.send_message(
                    {"res": f"User {user[b'username'].decode()} authenticated"}
                )
                return

            self.send_message(
                {
                    "res": f"Authentication failure..."
                }
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("flag")
    def flag_handler(self, msg):
        if self.current_user is not None:
            self.send_message(
                {
                    "res": f"Our authentication system is extremely secure... Here is a flag to celebrate: {self.flag}"
                }
            )
        else:
            self.send_message({"res": "Nope... Login first!"})

    @on_command("logout")
    def logout_handler(self, msg):
        if self.current_user is None:
            self.send_message({"res": "You are already logged out."})
        else:
            self.send_message({"res": "You have been logged out."})
            self.current_user = None


if __name__ == "__main__":
    flag = "flag{test_flag}"
    StrangeAuthenticationServer.start_server("0.0.0.0", 50505, flag=flag)
