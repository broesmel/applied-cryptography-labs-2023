#!/usr/bin/env python3
import secrets
from boilerplate import CommandServer, on_command
from Crypto.Protocol.KDF import HKDF
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256


class MacAndEncrypt(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.auth_key = secrets.token_bytes(16)
        master_secret = secrets.token_bytes(16)
        self.enc_key = HKDF(master_secret, 16, "encryption".encode(), SHA256)
        self.auth_key = HKDF(master_secret, 16, "authentication".encode(), SHA256)

        super().__init__(*args, **kwargs)

    def encrypt_msg(self, msg):
        """Given some message, encrypts it and gets the mac tag for it."""
        h = HMAC.new(self.auth_key, digestmod=SHA256)
        h.update(msg.encode())
        mac_tag = h.hexdigest()
        cipher = AES.new(self.enc_key, AES.MODE_CTR)
        encrypted_msg = cipher.encrypt(msg.encode())
        nonce = cipher.nonce
        return (mac_tag, encrypted_msg.hex(), nonce.hex())

    @on_command("flag")
    def token_handler(self, msg):
        """Ask the server for the encryption of the flag"""
        tag, ctxt, nonce = self.encrypt_msg(self.flag)
        self.send_message({"nonce": nonce, "ctxt": ctxt, "mac_tag": tag})

    @on_command("encrypt")
    def encrypt_handler(self, msg):
        """An encryption oracle. Given a message, it returns an encryption of it."""
        try:
            plaintext = msg["ptxt"]
            tag, ctxt, nonce = self.encrypt_msg(plaintext)
            self.send_message({"nonce": nonce, "enc_flag": ctxt, "mac_tag": tag})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})

    @on_command("decrypt")
    def decryption_handler(self, msg):
        """This tries to decrypt a message and verifies the mac tag.
        It won't return the plaintext to you though. Instead it will only tell you if decryption worked or not."""
        try:
            ctxt = bytes.fromhex(msg["ctxt"])
            nonce = bytes.fromhex(msg["nonce"])
            mac = bytes.fromhex(msg["mac_tag"])
            cipher = AES.new(self.enc_key, AES.MODE_CTR, nonce=nonce)
            ptxt = cipher.decrypt(ctxt)
            print(f"Decrypted: {ptxt}")
            h = HMAC.new(self.auth_key, digestmod=SHA256)
            h.update(ptxt)
            try:
                h.verify(mac)
                self.send_message({"success": True})
            except Exception as e:
                # Verification failed.
                self.send_message({"success": False})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag_test_flag_atmosphere}"
    MacAndEncrypt.start_server("0.0.0.0", 50604, flag=flag)
