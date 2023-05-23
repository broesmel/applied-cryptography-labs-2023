#!/usr/bin/env python

# from Crypto.Hash import 

class CBC_HMAC():
    def __init__(self, enc_key_len: int = 16, mac_key_len: int = 16, key: bytes = None):
        """Initialize the AEAD cipher.

        Keyword arguments:
        enc_key_len  -- byte length of the encryption key
        mac_key_len  -- byte length of the mac key
        key          -- key bytes
        """

        self.enc_key_len = enc_key_len
        self.mac_key_len = mac_key_len
        self.tag_len = 32

        # a correctly sized key must always be provided by the caller
        if not len(key) == self.mac_key_len + self.enc_key_len:
            raise ValueError("Bad key len")

        self.mac_key = key[ :mac_key_len]
        self.enc_key = key[-enc_key_len:]

        self.block_len = 16


def main():
    aead = CBC_HMAC(16, 16, bytes(range(32)))
    print((aead.mac_key + aead.enc_key).hex())

if __name__ == "__main__":
    main()
