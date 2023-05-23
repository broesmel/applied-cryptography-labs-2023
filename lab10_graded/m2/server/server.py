import secrets
from typing import Tuple
from Crypto.Cipher import AES

from Crypto.Hash import SHA256
from boilerplate import CommandServer, on_command

from Crypto.Protocol.KDF import HKDF
from Crypto.Util.number import isPrime

def DHIES_encrypt(g: int, p: int, message: bytes, pk_other: int) -> Tuple[int, bytes, bytes, bytes]:
    # Generate our ephemeral private key
    sk = secrets.randbelow((p-1)//2) + 1
    print(f"{sk=}")
    pk = pow(g, sk, p)

    pk_bytes = pk.to_bytes(512, "big")

    # Compute shared Diffie-Hellman value
    shared = pow(pk_other, sk, p)
    shared_bytes = shared.to_bytes(512, "big")

    pk_other_bytes = pk_other.to_bytes(512, "big")

    # Compute symmetric key
    K: bytes = HKDF(shared_bytes + pk_bytes + pk_other_bytes, 32, salt=b"", num_keys=1, context=b"dhies-enc", hashmod=SHA256) #type: ignore
    cipher = AES.new(K, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message)
    return pk, ciphertext, tag, cipher.nonce


class DHIESServer(CommandServer):
    def __init__(self, flag: str, *args, **kwargs):
        self.flag = flag
        self.encrypt_query_done = False
        self.parameters_set = False
        super().__init__(*args, **kwargs)

    @on_command("set_params")
    def handle_set_params(self, msg):
        if self.parameters_set:
            self.send_message({"error": "Parameters are already set!"})
            return

        try:
            p = msg["p"]
            g = msg["g"]

            # Some sanity checks
            if p <= 0:
                raise ValueError("p must be positive")

            if p.bit_length() < 1024:
                raise ValueError("p is too small")

            if p.bit_length() > 2048:
                raise ValueError("Ok, let's not go too wild, now")

            if not isPrime(p):
                raise ValueError("p must be prime")

            g %= p

            if g in (0, 1, p-1):
                raise ValueError("Invalid value for g")

            # Save parameters
            self.g = g
            self.p = p

            # Generate Bob's private and public key

            # Private key in the range 1 <= bob_privkey < (p-1)//2
            bob_privkey = secrets.randbelow((p-1)//2) + 1
            print(f"{bob_privkey=}")
            self.bob_pubkey = pow(g, bob_privkey, p)

            self.send_message({"res": "Thank you for the parameters, kind stranger!", "bob_pubkey": self.bob_pubkey})

            self.parameters_set = True
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})


    @on_command("encrypt")
    def handle_encrypt(self, msg):
        if self.encrypt_query_done:
            self.send_message({"error": "You're asking too much..."})
            return

        if not self.parameters_set:
            self.send_message({"error": "You must set parameters first"})
            return

        try:
            pk, ciphertext, tag, nonce = DHIES_encrypt(self.g, self.p, self.flag.encode(), self.bob_pubkey)
            self.send_message({"pk": pk, "ciphertext": ciphertext.hex(), "tag": tag.hex(), "nonce": nonce.hex()})
            self.encrypt_query_done = True
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    DHIESServer.start_server("0.0.0.0", 51002, flag=flag)
