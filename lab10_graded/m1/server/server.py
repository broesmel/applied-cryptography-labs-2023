import secrets
from typing import Tuple
from boilerplate import CommandServer, on_command

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

# This is a Mersenne prime
# Fun fact: p mod 4 == 3!
p = 2**127 - 1
TAG_LEN = 16

def create_MAC_tag(mac_key: bytes, message: bytes, mask: bytes) -> bytes:
    assert len(mac_key) == 32
    assert len(mask) == 16

    K: int = int.from_bytes(mac_key, "big") % p
    c: int = int.from_bytes(message, "big") % p
    mask_int: int = int.from_bytes(mask, "big") % p

    h = (K**3  + c * K**2 + len(message) * K) % p
    tag = (h + mask_int) % p
    print(K**2 % p)
    print(tag)
    return tag.to_bytes(TAG_LEN, "big")

def verify_MAC_tag(mac_key: bytes, message: bytes, mask: bytes, tag: bytes) -> bool:
    computed_tag = create_MAC_tag(mac_key, message, mask)
    return computed_tag == tag

def derive_keys(key: bytes):
    cipher_key: bytes = HKDF(key, 16, salt=b"", hashmod=SHA256, context=b"exodia-enc", num_keys=1) #type: ignore
    mac_key: bytes = HKDF(key, 32, salt=b"", hashmod=SHA256, context=b"exodia-mac", num_keys=1) #type: ignore

    return cipher_key, mac_key


def encrypt(key: bytes, message: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
    assert len(message) == 15

    cipher_key, mac_key = derive_keys(key)
    cipher = AES.new(cipher_key, AES.MODE_CTR, nonce=nonce, initial_value=0)

    # We use the first counter value to generate the MAC mask
    mask = cipher.encrypt(b'\x00' * 16)

    # Then, all successive counter values are used for CTR mode encryption
    ciphertext = cipher.encrypt(message)

    tag = create_MAC_tag(mac_key, ciphertext, mask)
    return ciphertext, tag

def decrypt(key: bytes, ciphertext: bytes, nonce: bytes, tag: bytes) -> bytes:
    cipher_key, mac_key = derive_keys(key)

    cipher = AES.new(cipher_key, AES.MODE_CTR, nonce=nonce, initial_value=0)

    # Again, we use the first counter value to generate the MAC mask
    # For CTR mode encrypt is the same as decrypt
    mask = cipher.decrypt(b'\x00' * 16)
    message = cipher.decrypt(ciphertext)
    print(message)
    if not verify_MAC_tag(mac_key, ciphertext, mask, tag):
        raise ValueError("Decryption failed")
    
    return message


class ExodiaServer(CommandServer):
    def __init__(self, flag: str, *args, **kwargs):
        self.flag = flag
        self.key = secrets.token_bytes(16)
        super().__init__(*args, **kwargs)

    @on_command("encrypt")
    def handle_encrypt(self, msg):
        """ The encryption oracle, much like the lectures, takes in a message and a nonce. We assume the adversary to be nonce-respecting."""

        try:
            message = msg["message"]

            if len(message) != 15:
                raise ValueError("Message is of the wrong size")

            if message == "Give me a flag!":
                raise ValueError("LMAO nice try")

            nonce = bytes.fromhex(msg["nonce"])

            if len(nonce) != 8:
                raise ValueError("Nonce is of the wrong size")

            ciphertext, tag = encrypt(self.key, message.encode(), nonce)
            self.send_message({"ciphertext": ciphertext.hex(), "tag": tag.hex()})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

    @on_command("decrypt")
    def handle_decrypt(self, msg):
        """ The decryption oracle tries to decrypt the given ciphertext

        If the message decrypts correctly and is equal to 'Give me a flag!' it will return the flag
        """

        try:
            ciphertext = bytes.fromhex(msg["ciphertext"])
            tag = bytes.fromhex(msg["tag"])
            nonce = bytes.fromhex(msg["nonce"])

            # Some sanity checks...
            if len(ciphertext) != 15:
                raise ValueError("Ciphertext is of the wrong size")

            if len(tag) != TAG_LEN:
                raise ValueError("Tag is of the wrong size")

            plaintext = decrypt(self.key, ciphertext, nonce, tag).decode()

            if plaintext == "Give me a flag!":
                self.send_message({"res": f"Wait. That's illegal. {self.flag}"})
            else:
                self.send_message({"res": f"We'll take that into consideration. *throws plaintext into the bin*"})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters: {type(e).__name__} {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    ExodiaServer.start_server("0.0.0.0", 51001, flag=flag)
