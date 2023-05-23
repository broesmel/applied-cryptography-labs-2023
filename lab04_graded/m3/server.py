import secrets
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TARGET = 10

def blockify(a):
    return [a[i : i + 16] for i in range(0, len(a), 16)]


class CBCServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.key = secrets.token_bytes(16)
        self.successes = 0
        self.secret_byte = b''

        super().__init__(*args, **kwargs)

    @on_startup()
    def generate_secret_byte(self):
        self.secret_byte = secrets.token_bytes(1)

    @on_command("decrypt")
    def handle_encrypt(self, msg):
        self.send_message(
            {"error": "Sorry, we haven't implemented encryption... uh, decryption yet"}
        )

    @on_command("encrypt")
    def handle_decrypt(self, msg):
        try:
            file_name = msg["file_name"].encode()
            data = bytes.fromhex(msg["data"])

            ptxt = (
                b"filename="
                + file_name
                + b"&data="
                + data
                + b"&secret_byte="
                + self.secret_byte
            )

            iv = secrets.token_bytes(AES.block_size)
            cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
            ptxt_pad = pad(ptxt, AES.block_size)
            ctxt = cipher.decrypt(ptxt_pad)

            self.send_message({"iv": iv.hex(), "ctxt": ctxt.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("solve")
    def handle_solve(self, msg):
        try:
            solve = bytes.fromhex(msg["solve"])
            if solve == self.secret_byte:
                self.successes += 1
                self.send_message({"res": f"Success! ({self.successes}/{TARGET})"})
            else:
                self.send_message({"res": "Nope."})
                self.close_connection()

            self.generate_secret_byte()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        if self.successes >= TARGET:
            self.send_message({"flag": self.flag})
            return

        self.send_message({"res": "Not enough solves!"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    CBCServer.start_server("0.0.0.0", 50403, flag=flag)
