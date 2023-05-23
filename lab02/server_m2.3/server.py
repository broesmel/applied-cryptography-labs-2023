import secrets
from string import ascii_letters, digits
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class ECBEncOracle(CommandServer):
    def __init__(self, key, flag, *args, **kwargs):
        self.key = key
        self.cipher = AES.new(self.key, AES.MODE_ECB)
        self.flag = flag
        self.successes = 0
        super().__init__(*args, **kwargs)

    def encrypt(self, plaintext: bytes):
        padded_plaintext = pad(plaintext, self.cipher.block_size)
        return self.cipher.encrypt(padded_plaintext)

    @on_command("encrypt")
    def encrypt_handler(self, msg):
        try:
            prepend_pad = bytes.fromhex(msg["prepend_pad"])
            result = self.encrypt(prepend_pad + self.flag.encode())
            self.send_message({"res": result.hex()})
        except Exception as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

if __name__ == "__main__":
    # You can sample a new key by doing key = os.urandom(16)
    key = b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F'
    flag = 'flag{test_flag}'
    ECBEncOracle.start_server("0.0.0.0", 50222, key=key, flag=flag)
