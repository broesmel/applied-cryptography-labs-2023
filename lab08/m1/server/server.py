#!/usr/bin/env python3
from boilerplate import CommandServer, on_command

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

from typing import Optional


class RSADecryptionOracle(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag

        self.key = RSA.generate(1024)

        super().__init__(*args, **kwargs)

    def encrypt(self, ptxt: str):
        ptxt_int = bytes_to_long(ptxt.encode())
        ctxt = pow(ptxt_int, self.key.e, self.key.n)
        return hex(ctxt)[2:]

    def decrypt(self, ctxt: int) -> Optional[bytes]:
        msg = pow(ctxt, self.key.d, self.key.n)
        msg_bytes = long_to_bytes(msg)

        if b"flag" in msg_bytes:
            return None
        else:
            return msg_bytes

    @on_command("encrypted_flag")
    def encrypted_flag_handler(self, msg):
        self.send_message(
            {
                "res": "Here is the encrypted flag",
                "encypted_flag": self.encrypt(self.flag),
                "N": hex(self.key.n)[2:],
                "e": hex(self.key.e)[2:],
            }
        )

    @on_command("decrypt")
    def decrypt_handler(self, msg):
        if "ciphertext" not in msg:
            self.send_message({"error": "No ciphertext to decrypt"})
            return

        ctxt = msg["ciphertext"]
        try:
            ctxt_int = int(ctxt, 16)
        except (ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})
            return

        ptxt = self.decrypt(ctxt_int)

        if ptxt is None:
            self.send_message({"error": "Yeah, you'd wish it'd be THAT easy, right?"})
            return

        self.send_message({"res": ptxt.hex()})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    RSADecryptionOracle.start_server("0.0.0.0", 50801, flag=flag)
