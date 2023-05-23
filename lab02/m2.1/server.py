import secrets
from string import ascii_letters, digits
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

TARGET = 5
ALPHABET = ascii_letters + digits

class ECBEncOracle(CommandServer):
    def __init__(self, key, flag, *args, **kwargs):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.flag = flag
        self.successes = 0
        self.message = ''
        super().__init__(*args, **kwargs)

    def encrypt(self, plaintext: bytes):
        padded_plaintext = pad(plaintext, self.cipher.block_size)
        return self.cipher.encrypt(padded_plaintext)

    @on_startup()
    def generate_secret_string(self):
        message_len = secrets.randbelow(32) + 1
        self.message = ''.join(secrets.choice(ALPHABET) for _ in range(message_len))

    @on_command("encrypt")
    def encrypt_handler(self, msg):
        try:
            prepend_pad = bytes.fromhex(msg["prepend_pad"])
            result = self.encrypt(prepend_pad + self.message.encode())
            self.send_message({"res": result.hex()})
        except Exception as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

    @on_command("solve")
    def solve_handler(self, msg):
        try:
            solve = msg["solve"]
            if solve == self.message[-1]:
                self.successes += 1
                self.send_message({"res": f"Success! ({self.successes}/{TARGET})"})
            else:
                self.send_message({"res": "Nope."})
                self.close_connection()

            self.generate_secret_string()
        except Exception as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

        if self.successes == TARGET:
            self.send_message({"flag": self.flag})


if __name__ == "__main__":
    # You can sample a new key by doing key = os.urandom(16)
    key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
    flag = 'flag{test_flag}'
    ECBEncOracle.start_server("0.0.0.0", 50221, key=key, flag=flag)
