#!/usr/bin/env python3
import os
import secrets
import time

from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class Server(CommandServer):
    """ Server implements a simple secure server which takes commands from a client
    and executes them.
    """

    def __init__(self, key, flag, *args, **kwargs):
        self.flag = flag

        self.block_size = 16
        self.k = key

        super().__init__(*args, **kwargs)

    def send_encrypted_message(self, msg):
        cipher = AES.new(self.k, AES.MODE_CBC)
        ctxt = cipher.encrypt(pad(msg.encode(), self.block_size))
        encrypted_res = cipher.iv + ctxt
        self.send_message({"res": encrypted_res.hex()})

    def ls_handler(self):
        self.send_encrypted_message(str(os.listdir()))

    def time_handler(self):
        self.send_encrypted_message(time.ctime())

    def cat_handler(self):
        self.send_encrypted_message("Not yet implemented.")

    @on_command("encrypted_command")
    def encrypted_command_handler(self, msg):
        try:
            encrypted_command = bytes.fromhex(msg["encrypted_command"])
            iv = encrypted_command[:self.block_size]
            ctxt = encrypted_command[self.block_size:]

            cipher = AES.new(self.k, AES.MODE_CBC, iv = iv)
            command = unpad(cipher.decrypt(ctxt), self.block_size).decode()
            command_parts = command.split(" ")

            match command_parts[0]:
                case "ls":
                    self.ls_handler()
                case "time":
                    self.time_handler()
                case "cat":
                    self.cat_handler()
                case _:
                    raise ValueError(f"No such command. But here's a flag for you: {self.flag}")

        except (KeyError,ValueError) as e:
            self.send_encrypted_message(repr(e))

if __name__ == "__main__":
    key = secrets.token_bytes(16)
    flag = 'flag{test_flag}'
    Server.start_server("localhost", 50343, key=key, flag=flag)
