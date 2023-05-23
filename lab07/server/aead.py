# based on
# https://datatracker.ietf.org/doc/html/draft-mcgrew-aead-aes-cbc-hmac-sha2-05

from Crypto.Hash import SHA384, HMAC

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
        self.tag_len = mac_key_len

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

        hmac = HMAC.new(key=self.mac_key, digestmod=SHA384)
        hmac.update(add_data)
        hmac.update(iv+S)
        hmac.update(AL)

        T = hmac.digest()[:-self.tag_len] # conform to the spec

        ct = S
        tag = T

        return (iv + ct) + tag
    
    def decrypt(self, C: bytes, A: bytes = b'')-> bytes:
        """Compute plaintext and MAC tag for verification.

        Keyword arguments:
        C -- iv + ciphertext
        A -- additional data
        """

        iv = C[:self.block_len]
        S = C[self.block_len:-self.tag_len]
        T = C[-self.tag_len:]
        
        # 64 bits is 8 bytes, network byte orde is big, unsigned
        add_data_bitlen = len(A) * 8 
        AL = add_data_bitlen.to_bytes(8, 'big', signed=False)

        hmac = HMAC.new(key=self.mac_key, digestmod=SHA384)
        hmac.update(A)
        hmac.update(iv+S)
        hmac.update(AL)

        tag = hmac.digest()[:-self.tag_len]
        if tag != T: raise ValueError('tag mismatch')

        cipher = AES.new(self.enc_key, AES.MODE_CBC, iv=iv)
        P_PS = cipher.decrypt(S)
        P = unpad(P_PS, self.block_len)

        return P



def main():
    key = '41206c6f6e6720726561642061626f75742073797374656d64206973207768617420796f75206e65656420616674657220746865206c6162'
    ct = 'bb74c7b9634a382df5a22e0b744c6fda63583e0bf0e375a8a5ed1a332b9e0f78aab42a19af61745e4d30c3d04eeee23a7c17fc97d442738ef5fa69ea438b21e1b07fb71b37b52385d0e577c3b0c2da29fb7ae10060aa1f4b486f1d8e27cca8ab7df30af4ad0db52e'
    ad = ''


    key = bytes.fromhex(key)
    ct = bytes.fromhex(ct)
    ad = bytes.fromhex(ad)
    print(CBC_HMAC(32, 24, key).decrypt(ct, ad))


if __name__ == "__main__":
    main()
