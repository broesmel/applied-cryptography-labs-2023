#!/usr/bin/env python3
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Util import number


class RSAUnderConstruction(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag

        self.N = None
        self.e = None
        self.d = None

        super().__init__(*args, **kwargs)

    def getSuitablePrime(self):
        while True:
            p = number.getPrime(2048)
            if (p - 1) % 3 != 0:
                return p

    @on_startup()
    def keygen(self):
        p, q = self.getSuitablePrime(), self.getSuitablePrime()
        self.N = p * q
        self.e = 3
        phiN = (p - 1) * (q - 1)
        self.d = number.inverse(self.e, phiN)

    @on_command("encrypted_flag")
    def encrypted_flag_handler(self, msg):
        int_flag = int.from_bytes(self.flag.encode(), byteorder="big")
        self.encrypt_handler({"plaintext": str(int_flag)})

    @on_command("encrypt")
    def encrypt_handler(self, msg):
        if "plaintext" not in msg:
            self.send_message({"error": "No plaintext to encrypt"})
            return
        ptxt = msg["plaintext"]

        try:
            ptxt_int = int(ptxt)
        except (ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})
            return

        ctxt_int = pow(ptxt_int, self.e, self.N)

        self.send_message({"N": str(self.N), "e": str(self.e), "ctxt": str(ctxt_int)})

    @on_command("decrypt")
    def decrypt_handler(self, msg):
        self.send_message({"res": "Under construction"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    RSAUnderConstruction.start_server("0.0.0.0", 50802, flag=flag)
