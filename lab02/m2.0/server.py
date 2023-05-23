from boilerplate import CommandServer, on_command, on_startup

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

KEY_SIZE = 16

class ECBEncOracle(CommandServer):
    def __init__(self, key, message, flag, *args, **kwargs):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.message = message
        self.flag = flag
        super().__init__(*args, **kwargs)

    def encrypt(self, plaintext: bytes):
        padded_plaintext = pad(plaintext, self.cipher.block_size)
        return self.cipher.encrypt(padded_plaintext)

    def decrypt(self, ciphertext: bytes):
        return self.cipher.decrypt(ciphertext)

    @on_command("encrypt")
    def encrypt_handler(self, msg):
        try:
            prepend_pad = bytes.fromhex(msg["prepend_pad"])
            result = self.encrypt(prepend_pad + self.message)
            self.send_message({"res": result.hex()})
        except Exception as e:
            self.send_message({"res": f"Invalid parameters: {e}"})

    @on_command("solve")
    def solve_handler(self, msg):
        try:
            solve_ciphertext = bytes.fromhex(msg["ciphertext"])
            plaintext_pad = self.decrypt(solve_ciphertext)
            plaintext = unpad(plaintext_pad, self.cipher.block_size)

            if plaintext.decode() == 'flag, please!':
                self.send_message({"flag": self.flag})
            else:
                self.send_message({"res": "Nope."})
        except Exception as e:
            self.send_message({"res": f"Invalid parameters: {e}"})


if __name__ == "__main__":
    # You can sample a new key by doing key = os.urandom(16)
    key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
    message = b'Know thyself, nothing to excess, certainty brings ruin.'
    flag = 'flag{test_flag}'
    ECBEncOracle.start_server("0.0.0.0", 50220, key=key, message=message, flag=flag)
