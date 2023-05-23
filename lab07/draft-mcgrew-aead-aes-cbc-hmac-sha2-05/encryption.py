from Crypto.Hash import SHA256, HMAC

from Crypto.Util.Padding import pad, unpad

from Crypto.Cipher import AES

from secrets import token_bytes

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


    def encrypt(self, pt: bytes, add_data: bytes = b'', iv: bytes = None):
        """Compute ciphertext and MAC tag.

        Keyword arguments:
        pt       -- plaintext
        add_data -- additional data
        iv       -- initialization vector
        """
        if iv is None:
            # Choose random IV.
            iv = token_bytes(self.block_len)
    
        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv=iv)
        P_PS = pad(pt, self.block_len)
        S = cipher.encrypt(P_PS)

        # 64 bits is 8 bytes, network byte orde is big, unsigned
        add_data_bitlen = len(add_data) * 8 
        AL = add_data_bitlen.to_bytes(8, 'big', signed=False)

        hmac = HMAC.new(key=self.mac_key, digestmod=SHA256)
        hmac.update(add_data)
        hmac.update(iv+S)
        hmac.update(AL)

        T = hmac.digest()[:-16]# [:16] # strip off the final 16 bytes? [:-16]

        ct = S
        tag = T

        return (iv + ct) + tag

def main():
    test_key = bytes.fromhex("""000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f""")
    test_pt = bytes.fromhex("""41206369706865722073797374656d206d757374206e6f7420626520726571756972656420746f206265207365637265742c20616e64206974206d7573742062652061626c6520746f2066616c6c20696e746f207468652068616e6473206f662074686520656e656d7920776974686f757420696e636f6e76656e69656e6365""")
    test_iv = bytes.fromhex("1af38c2dc2b96ffdd86694092341bc04")
    test_ad = bytes.fromhex("""546865207365636f6e64207072696e6369706c65206f662041756775737465204b6572636b686f666673""")
    test_c = bytes.fromhex("""1af38c2dc2b96ffdd86694092341bc04c80edfa32ddf39d5ef00c0b468834279a2e46a1b8049f792f76bfe54b903a9c9a94ac9b47ad2655c5f10f9aef71427e2fc6f9b3f399a221489f16362c703233609d45ac69864e3321cf82935ac4096c86e133314c54019e8ca7980dfa4b9cf1b384c486f3a54c51078158ee5d79de59fbd34d848b3d69550a67646344427ade54b8851ffb598f7f80074b9473c82e2db652c3fa36b0a7c5b3219fab3a30bc1c4""")

    assert CBC_HMAC(16, 16, test_key).encrypt(test_pt, test_ad, test_iv) == test_c

    pt = b"Just plaintext\x02\x00"
    print(SHA256.new(
        data=CBC_HMAC(16, 16, test_key).encrypt(pt, iv=test_iv)
        ).hexdigest())

if __name__ == "__main__":
    main()
