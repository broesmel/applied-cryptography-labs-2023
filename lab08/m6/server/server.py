#!/usr/bin/env python3
import secrets 
import random
import datetime
import time
import numpy 

from Crypto.Util import number
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

from boilerplate import CommandServer, on_command

E = 65537

class SecureRSAServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag 
        self.secret = int.from_bytes(secrets.token_bytes(16), 'big')
        self.rsa_keys = []

        super().__init__(*args, **kwargs)

    def make_random_stream(self, seed: int):
        """Use Numpy to generate a random stream from a specific seed. 
        Because I multiply it by 16 random bytes this must be secure."""
        
        #seed = 0
        numpy.random.seed((seed * self.secret) % 2**32)
        
        print(f"Seed: {(seed * self.secret) % 2**32=}")
        return lambda n: numpy.random.bytes(n)

    def keygen(self):
        """Generates an RSA key. Repeatedly picks p and q, until they are coprime to E"""
        while True:
            t = datetime.datetime.now().second
            r = random.randint(1, 10)
            p = number.getPrime(1024, randfunc=self.make_random_stream(t))
            q = number.getPrime(1024, randfunc=self.make_random_stream(t+r))
            if (p-1) % E == 0 or (q-1) % E == 0:
                continue
            N = p*q
            phiN = (p-1)*(q-1)
            d = number.inverse(E, phiN)
            time.sleep(1)
            print(f"Generated key in {t=}, {r=}; with N={str(N)[:3]}, p={str(p)[:3]}, q={str(q)[:3]}, d={str(d)[:3]}")
            return RSA.construct((N, E, d))

    @on_command("encrypt")
    def encrypt_handler(self, msg):
        """Encrypt the flag using a key index the sender gets to choose"""
        try:
            index = msg["index"]
            if index >= len(self.rsa_keys):
                self.send_message({'err': 'bad request. Index too large'})
                return
            keys = self.rsa_keys[index]
            cipher = PKCS1_OAEP.new(keys)
            c = cipher.encrypt(self.flag.encode()).hex()
            self.send_message({'key': index, 'encrypted_flag': c })
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})


    @on_command("generate")
    def generate_handler(self, msg):
        """Call this to make the server generate a new RSA key"""
        new_key = self.keygen()
        self.rsa_keys.append(new_key)
        parameters = {
            'N' : new_key.n,
            'e' : new_key.e,
            'key_index' : len(self.rsa_keys) - 1
            }
        self.send_message(parameters)



if __name__ == "__main__":
    flag = "flag{test_flag_1}"
    SecureRSAServer.start_server('0.0.0.0', 50806, flag=flag)