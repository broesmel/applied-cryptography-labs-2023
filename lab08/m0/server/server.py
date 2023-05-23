#!/usr/bin/env python3
from boilerplate import CommandServer, on_command

from Crypto.Util import number

# this is what you implemented in this lab
from rsa import rsa_enc


class RSAEncryptionServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.nbits = 2048

        self.N = None
        self.e = None

        super().__init__(*args, **kwargs)

    def textbook_rsa_parameters_check(self, N, e, d, p, q):
        if not (number.isPrime(p) and number.size(p) <= self.nbits):
            return "p is not a prime"
        if not (number.isPrime(q) and number.size(q) <= self.nbits):
            return "q is not a prime"
        if not N == p * q:
            return "N not equal p * q"
        if not number.size(N) == self.nbits:
            return f"N does not have {self.nbits} bits"
        phi_N = (p - 1) * (q - 1)
        if not number.GCD(e, phi_N) == 1:
            return "e is not co-prime to PHI(N)"
        if not e == number.inverse(d, phi_N):
            return "d is not the inverse of e mod PHI(N)"
        return None

    @on_command("set_parameters")
    def set_parameters_handler(self, msg):
        try:
            N, e, d, p, q = (
                int(msg["N"]),
                int(msg["e"]),
                int(msg["d"]),
                int(msg["p"]),
                int(msg["q"]),
            )
            error_msg = self.textbook_rsa_parameters_check(N, e, d, p, q)
            if error_msg is not None:
                self.send_message({"error": error_msg})
                return
            self.N, self.e = (N, e)
            self.send_message({"res": "RSA Parameters were successfully updated"})
        except (KeyError, ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

    @on_command("encrypted_flag")
    def encrypted_flag(self, msg):
        if None in (self.N, self.e):
            self.send_message({"error": "Please successfully set the RSA parameters"})
            return
        int_flag = int.from_bytes(self.flag.encode(), "big")
        enc_flag = rsa_enc((self.N, self.e), int_flag)
        self.send_message(
            {"res": f"Here is your flag... oh no, it is RSA encrypted: {enc_flag}"}
        )


if __name__ == "__main__":
    flag = "flag{test_flag}"
    RSAEncryptionServer.start_server("0.0.0.0", 50800, flag=flag)
