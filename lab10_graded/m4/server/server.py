import secrets
from boilerplate import CommandServer, on_command

from Crypto.PublicKey import RSA
from Crypto.Hash import SHAKE256

RSA_KEYLEN = 1024 # 1024-bit modulus
RAND_LEN = 256 # 256-bit of randomness for masking
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8

def xor(a: bytes, b: bytes) -> bytes:
    assert len(a) == len(b), f"{len(a)}, {len(b)}"
    return bytes(x ^ y for x, y in zip(a, b))

def RSA_pad_encrypt(e: int, N: int, ptxt: bytes) -> bytes:
    if len(ptxt) >= P_LEN:
        raise ValueError("Message too long to encrypt")

    rand = secrets.token_bytes(RAND_LEN // 8)

    # We use SHAKE256 in order to implement a hash function with output size of our liking
    rand_hashed = SHAKE256.new(rand).read(P_LEN)

    ptxt_padded = b"\x00" * (P_LEN - len(ptxt) - 1) + b"\x01" + ptxt
    assert len(ptxt_padded) == P_LEN

    ptxt_masked = xor(rand_hashed, ptxt_padded)


    m = int.from_bytes(b'\x00' + rand + ptxt_masked, "big")

    print(f"{ptxt=}")
    m_bytes = m.to_bytes(RSA_KEYLEN // 8, 'big')
    print(f"{m_bytes.hex()=}")



    return pow(m, e, N).to_bytes(RSA_KEYLEN // 8, 'big'), m_bytes

def RSA_decrypt_unpad(d: int, N: int, ctxt: bytes) -> bytes:
    m = pow(int.from_bytes(ctxt, "big"), d, N).to_bytes(RSA_KEYLEN // 8, 'big')
    
    m_decr = pow(int.from_bytes(ctxt, "big"), d, N)

    if m[0] != 0:
        raise ValueError("Error: Decryption failed")

    rand = m[1:1+RAND_LEN//8]
    ptxt_masked = m[1+RAND_LEN//8:]

    rand_hashed = SHAKE256.new(rand).read(P_LEN)
    ptxt_padded = xor(ptxt_masked, rand_hashed)

    for i, b in enumerate(ptxt_padded):
        if b == 1 and all(ch == 0 for ch in ptxt_padded[:i]):
            return ptxt_padded[i+1:]
    else:
        raise ValueError("Eror: Decryption failed")

class SuboptimalRSAServer(CommandServer):
    def __init__(self, flag: str, *args, **kwargs):
        # NOTE: we guarantee that the flag (even in our offline tests) will always be short enough to be encrypted correctly
        self.flag = flag
        self.key = RSA.generate(RSA_KEYLEN)

        super().__init__(*args, **kwargs)

    @on_command("get_params")
    def get_params(self, msg):
        self.send_message({"N": self.key.n, "e": self.key.e})

    @on_command("flag")
    def handle_query(self, msg):
        enc_flag, m_bytes = RSA_pad_encrypt(self.key.e, self.key.n, self.flag.encode())
        self.send_message({"flag": enc_flag.hex(), "m_orig": m_bytes.hex()})

    @on_command("decrypt")
    def handle_guess(self, msg):
        try:
            ctxt = bytes.fromhex(msg["ctxt"])
            msg = RSA_decrypt_unpad(self.key.d, self.key.n, ctxt)
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})
        else:
            del msg
            self.send_message({"res": "Nom, nom, nom... This plaintext tasted nice!"})


if __name__ == "__main__":
    flag = "flag{test_flag}"
    SuboptimalRSAServer.start_server("0.0.0.0", 51004, flag=flag)
