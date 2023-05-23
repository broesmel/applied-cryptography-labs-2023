#!/usr/bin/env python

from Crypto.Hash import SHA256

from Crypto.Util.Padding import pad, unpad

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


    def _add_pt_padding(self, pt: bytes):
        """Return padded plaintext"""
        return pad(pt, self.block_len)

    def _remove_pt_padding(self, pt: bytes):
        """Return unpadded plaintext"""
        if not len(pt) % self.block_len == 0:
            raise ValueError("Bad decryption")
        return unpad(pt, self.block_len)


def main():
    aead = CBC_HMAC(16, 16, b''.join(bytes([i]) for i in range(32)))
    pt = b"Just plaintext\x02\x00"
    assert aead._remove_pt_padding(aead._add_pt_padding(pt)) == pt
    print(SHA256.new(data=aead._add_pt_padding(pt)).hexdigest())

if __name__ == "__main__":
    main()
