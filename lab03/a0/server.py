#!/usr/bin/env python3
from boilerplate import CommandServer, Message, on_command


class ExceptionsOracle(CommandServer):
    """This server accepts commands in hex representation."""

    def __init__(self, flag: str, *args, **kwargs):
        self.flag = flag
        super().__init__(*args, **kwargs)

    @on_command("hex_command")
    def hex_command_handler(self, msg: Message):
        if "hex_command" not in msg:
            self.send_message(
                {"res": "The hex representation of the command is required."}
            )
            return

        hex_command = msg["hex_command"]
        try:
            bytes_command = bytes.fromhex(hex_command)
        except (ValueError) as _:
            bytes_command = b"intro"

        try:
            command = bytes_command.decode()
        except (ValueError) as _:
            self.send_message({"res": self.flag})
            return

        match command:
            case "intro":
                self.intro_handler()
            case _:
                self.send_message({"res": "No such command: " + command})

    def intro_handler(self):
        self.send_message({"res": "Welcome to the oracle!"})


if __name__ == "__main__":
    flag = "flag{test_flag}"

    ExceptionsOracle.start_server("localhost", 50390, flag=flag)
