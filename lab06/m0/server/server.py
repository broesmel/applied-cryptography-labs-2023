#!/usr/bin/env python3
import secrets

from boilerplate import CommandServer, on_command, on_startup

from Crypto.Hash import SHA256

from typing import Optional


class AuthTokenCommandServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.key = secrets.token_bytes(16)

        super().__init__(*args, **kwargs)

    def mac(self, message: bytes) -> bytes:
        h = SHA256.new()
        h.update(self.key)
        h.update(message)
        return h.digest()

    def parse_and_check_token(self, token_dict: dict) -> Optional[dict]:
        if "command_string" not in token_dict:
            self.send_message({"error": "Command_string field missing"})
            return None

        if "mac" not in token_dict:
            self.send_message({"error": "MAC field missing"})
            return None

        command_string = bytes.fromhex(token_dict["command_string"])
        mac = self.mac(command_string).hex()

        if mac != token_dict["mac"]:
            self.send_message({"error": "Invalid MAC"})
            return None

        # Split the command string by & to obtain key-value pairs
        fragments = command_string.split(b"&")

        command_dict = {}

        for fragment in fragments:
            # Attempt to parse each fragment '{key}={value}'
            if b"=" in fragment:
                key, value = fragment.split(b"=", 1)
                command_dict[key.decode()] = value
            else:
                continue

        return command_dict

    @on_command("token")
    def token_handler(self, msg):
        command_string = b" "
        mac = self.mac(command_string).hex()

        # The command_string is hex encoded for... reasons...
        token = {
            "command_string": command_string.hex(),
            "mac": mac,
        }

        self.send_message(
            {"res": "Here is your token to issue commands.", "token": token}
        )

    @on_command("token_command")
    def token_command_handler(self, msg):
        if "token" not in msg:
            self.send_message({"error": "A token is required."})
            return
        token = msg["token"]

        try:
            command_dict = self.parse_and_check_token(token)

            if command_dict is None:
                return

            if command_dict["command"] == b"hello":
                self.send_message({"res": f"Hello {command_dict['arg'].decode()}!"})
            elif command_dict["command"] == b"flag":
                self.send_message({"res": f"Here is your flag: {self.flag}"})

        except Exception as e:
            self.send_message({"error": f"Invalid parameters: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    AuthTokenCommandServer.start_server("0.0.0.0", 50600, flag=flag)
