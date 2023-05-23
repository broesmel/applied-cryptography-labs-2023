import math
from typing import Tuple
from boilerplate import CommandServer, on_command

from Crypto.PublicKey import DSA
from Crypto.Hash import MD5, HMAC, SHA256

def get_nonce(msg: bytes, sign_key: int, g: int, p: int, q: int) -> Tuple[int, int]:
    # Because we don't trust our server, we will be hedging against randomness failures by derandomising

    h = MD5.new(msg).digest()

    # We begin by deterministically deriving a nonce
    # as specified in https://datatracker.ietf.org/doc/html/rfc6979#section-3.2
    l = 8 * MD5.digest_size
    rlen = math.ceil(q.bit_length() / 8)
    V = bytes([1] * l)
    K = bytes([0] * l)

    K = HMAC.new(K, V + b'\x00' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()
    K = HMAC.new(K, V + b'\x01' + sign_key.to_bytes(rlen, "big") + h).digest()
    V = HMAC.new(K, V).digest()

    while True:
        T = b''
        tlen = 0

        while tlen < q.bit_length():
            V = HMAC.new(K, V).digest()
            T += V
            tlen += len(V) * 8

        # Apply bits2int and bring down k to the length of q
        k = int.from_bytes(T, "big")
        k >>= k.bit_length() - q.bit_length()

        r = pow(g, k, p) % q

        if 1 <= k <= q-1 and r != 0:
            break

        K = HMAC.new(K, V + b'\x00').digest()
        V = HMAC.new(K, V).digest()

    return k, r


def DSA_sign(msg: bytes, sign_key: int, g: int, p: int, q: int):
    # Get k and r = (g^k mod p) mod q
    k, r = get_nonce(msg, sign_key, g, p, q)

    # Compute the signature
    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    s = (pow(k, -1, q) * (h + sign_key * r)) % q
    return r, s

def DSA_verify(r: int, s: int, msg: bytes, vfy_key: int, g: int, p: int, q: int) -> bool:
    if not (1 <= r <= q-1 and 1 <= s <= q-1):
        return False

    w = pow(s, -1, q)
    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    u1 = w * h % q
    u2 = w * r % q

    return (pow(g, u1, p) * pow(vfy_key, u2, p) % p) % q == r


class SigningServer(CommandServer):
    def __init__(self, flag: str, *args, **kwargs):
        self.flag = flag
        self.key = DSA.generate(2048)
        super().__init__(*args, **kwargs)

    @on_command("get_params")
    def handle_get_params(self, msg):
        self.send_message({"vfy_key": self.key.y, "g": self.key.g, "p": self.key.p, "q": self.key.q})

    @on_command("sign")
    def handle_sign(self, msg):
        try:
            message = bytes.fromhex(msg["message"])

            if message == b"Give me a flag!":
                raise ValueError("LMAO nice try")

            r, s = DSA_sign(message, self.key.x, self.key.g, self.key.p, self.key.q)
            self.send_message({"r": r, "s": s})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        try:
            r = msg["r"]
            s = msg["s"]

            if DSA_verify(r, s, b"Give me a flag!", self.key.y, self.key.g, self.key.p, self.key.q):
                self.send_message({"flag": self.flag})
            else:
                self.send_message({"error": "This ain't it, chief"})
                self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    SigningServer.start_server("0.0.0.0", 51000, flag=flag)
