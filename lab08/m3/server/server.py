#!/usr/bin/env python3
import secrets

from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from boilerplate import CommandServer, on_command, on_startup

PROB_PERC = 100


class FastKeyGenRSA(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag

        self.key = None
        self.cipher = None

        super().__init__(*args, **kwargs)

    def nextPrime(self, p: int):
        while True:
            p = p + 2
            if number.isPrime(p):
                return p

    def keygen_inner(self) -> tuple[int, int]:
        p = number.getPrime(2048)
        q = self.nextPrime(p)
        while secrets.randbelow(100) > PROB_PERC:
            q = self.nextPrime(q)
        return p, q

    @on_startup()
    def keygen(self):
        e = 65537
        p, q = self.keygen_inner()
        while (p - 1) % e == 0 or (q - 1) % e == 0:
            p, q = self.keygen_inner()
        print(f"{q-p=}")
        N = p * q
        phiN = (p - 1) * (q - 1)
        d = number.inverse(e, phiN)
        print(d)

        self.key = RSA.construct((N, e, d))
        self.cipher = PKCS1_OAEP.new(self.key)

    @on_command("encrypted_flag")
    def encrypted_flag_handler(self, msg):
        self.encrypt_handler({"plaintext": self.flag.encode().hex()})

    @on_command("encrypt")
    def encrypt_handler(self, msg):
        if "plaintext" not in msg:
            self.send_message({"error": "No plaintext to encrypt"})
            return
        ptxt_hex = msg["plaintext"]

        try:
            ptxt = bytes.fromhex(ptxt_hex)
        except (ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})
            return

        ctxt = self.cipher.encrypt(ptxt)

        self.send_message(
            {"N": str(self.key.n), "e": str(self.key.e), "ctxt": ctxt.hex()}
        )

    @on_command("decrypt")
    def decrypt_handler(self, msg):
        self.send_message({"res": "Under construction"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    FastKeyGenRSA.start_server("0.0.0.0", 50803, flag=flag)
