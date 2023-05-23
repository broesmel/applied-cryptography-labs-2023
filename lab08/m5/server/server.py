#!/usr/bin/env python3
import secrets
import math 

from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long

from boilerplate import CommandServer, on_command

class RSAServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag 
        self.key = RSA.generate(1024)
        self.phi = (self.key.p - 1) * (self.key.q - 1)
        super().__init__(*args, **kwargs)
        
    @on_command("pub_key")
    def pubkey_handler(self, msg):
        """Allows the querying of the public key"""
        self.send_message({
            "message": "When encrypting, remember to give me a public exponent",
            "N": hex(self.key.n)[2:]
        })

    @on_command("encrypt")
    def encrypt(self, msg):
        """Allows you to receive the flag encrypted for a value e of your choice""" 
        try:
            e = msg["e"] % self.phi

            if e == 1:
                self.send_message({"error": "You think you're really funny, eh? Arrivederci"})
                return 
            if math.gcd(e, self.phi) != 1:
                self.send_message({"error": "Yeah, no, give me another one"})
                return 
            
            flag_int = bytes_to_long(self.flag.encode())
            ctxt = pow(flag_int, e, self.key.n)
            self.send_message({"ciphertext":hex(ctxt)[2:]})

        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})




if __name__ == "__main__":
    flag = "flag{test_flag_1}"
    RSAServer.start_server('0.0.0.0', 50805, flag=flag)
