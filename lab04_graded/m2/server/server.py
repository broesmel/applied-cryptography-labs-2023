import secrets
from boilerplate import CommandServer, on_command

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def xor(a: bytes, b: bytes):
    return bytes(x ^ y for x, y in zip(a, b))


class IGEServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        key = secrets.token_bytes(16)
        self.flag_enc = None
        self.cipher = AES.new(key, AES.MODE_ECB)

        super().__init__(*args, **kwargs)

    def encrypt(self, msg):
        bs = self.cipher.block_size

        m0 = secrets.token_bytes(bs)
        c0 = secrets.token_bytes(bs)

        msg = pad(msg, bs)
        msg_blocks = [msg[i : i + bs] for i in range(0, len(msg), bs)]

        out_blocks = []
        m_prev = m0
        c_prev = c0

        for ptxt_block in msg_blocks:
            n = self.cipher.encrypt(xor(ptxt_block, c_prev))
            ctxt_block = xor(n, m_prev)

            m_prev = ptxt_block
            c_prev = ctxt_block

            out_blocks.append(ctxt_block)

        return m0, c0, b"".join(out_blocks)

    def decrypt(self, m0, c0, ctxt):
        bs = self.cipher.block_size
        ctxt_blocks = [ctxt[i : i + bs] for i in range(0, len(ctxt), bs)]

        out_blocks = []
        m_prev = m0
        c_prev = c0

        for ctxt_block in ctxt_blocks:
            n = xor(ctxt_block, m_prev)
            ptxt_block = xor(self.cipher.decrypt(n), c_prev)

            m_prev = ptxt_block
            c_prev = ctxt_block

            out_blocks.append(ptxt_block)

        return unpad(b"".join(out_blocks), bs)

    @on_command("flag")
    def handle_flag(self, msg):
        if not self.flag_enc:
            m0, c0, ctxt = self.encrypt(self.flag.encode())
            self.flag_enc = (m0, c0, ctxt)
        else:
            m0, c0, ctxt = self.flag_enc

        self.send_message({"m0": m0.hex(), "c0": c0.hex(), "ctxt": ctxt.hex()})

    @on_command("decrypt")
    def handle_decrypt(self, msg):
        try:
            ctxt = bytes.fromhex(msg["ctxt"])
            m0 = bytes.fromhex(msg["m0"])
            c0 = bytes.fromhex(msg["c0"])

            ptxt = self.decrypt(m0, c0, ctxt)

            # Can't leak plaintext if we delete it, right?
            del ptxt

            self.send_message(
                {
                    "res": "Thank you for your message! Due to the new security policies, we aren't allowed to disclose anything about the plaintext. Contact our customer service for more information."
                }
            )
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{very_looong_test_flag}"
    IGEServer.start_server("0.0.0.0", 50402, flag=flag)
