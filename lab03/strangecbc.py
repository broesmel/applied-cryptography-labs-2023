from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes

def xor(X: bytes, Y: bytes):
    # for i in range(len(X)):
        # c += bytes([X[i] ^ Y[i]])

    return bytes(x ^ y for (x, y) in zip(X, Y))


class StrangeCBC():
    def __init__(self, key: bytes, iv: bytes = None, block_length: int = 16):
        """Initialize the CBC cipher.
        """

        if iv is None:
            iv = get_random_bytes(block_length)

        self.iv = iv
        self.key = key
        self.block_length = block_length
        self.magic = int(1336).to_bytes(self.block_length, 'big')
        self.aes_ecb = AES.new(self.key, AES.MODE_ECB)
        # self.cipher = AES.new(self.key, AES.MODE_ECB)

    def encrypt(self, plaintext: bytes):
        """Encrypt the input plaintext using AES-128 in strange-CBC mode:

        C_i = E_k(P_i xor C_(i-1) xor 1336)
        C_0 = IV

        Uses IV and key set from the constructor.

        Args:
            plaintext (bytes): input plaintext.

        Returns:
            bytes: ciphertext, starting from block 1 (do not include the IV)
        """



        ciphertext = bytes()
        # print(f"BEFOR ENCRYPT {ciphertext.hex()=}, {plaintext.hex()=}")
        C_0 = self.iv
        # if(len(plaintext) % 16): 
        plaintext = pad(plaintext, self.block_length)
        
        for i in range(0, len(plaintext), self.block_length):
            if(i == 0):
                P_i = plaintext[i: i+self.block_length]
                P_i_xor_C_0 = xor(P_i, C_0)
                P_i_xor_C_0_xor_1336 = xor(P_i_xor_C_0, self.magic)
                C_i = self.aes_ecb.encrypt(P_i_xor_C_0_xor_1336)
                # print(f"{P_i.hex()=}, {C_i.hex()=}")
                ciphertext += C_i
            else:        
                P_i = plaintext[i: i+self.block_length]
                C_i_m1 = ciphertext[i-self.block_length: i]
                P_i_xor_C_i_m1 = xor(P_i, C_i_m1)
                P_i_xor_C_i_m1_xor_1336 = xor(P_i_xor_C_i_m1, self.magic)
                C_i = self.aes_ecb.encrypt(P_i_xor_C_i_m1_xor_1336)
                # print(f"{P_i.hex()=}, {C_i.hex()=}")
                ciphertext += C_i



        # print(f"AFTER ENCRYPT {ciphertext.hex()=}, {plaintext.hex()=}")
        return ciphertext

    def decrypt(self, ciphertext: bytes):
        """Decrypt the input ciphertext using AES-128 in strange-CBC mode.

        Uses IV and key set from the constructor.

        Args:
            ciphertext (bytes): input ciphertext.

        Returns:
            bytes: plaintext.
        """

        plaintext = bytes()
        # print(f"BEFOR DECRYPT {plaintext.hex()=}, {ciphertext.hex()=}")
        C_0 = self.iv
        for i in range(0, len(ciphertext), self.block_length):
            if(i == 0):
                C_i = ciphertext[i: i+self.block_length]
                P_i_xor_C_0_xor_1336 = self.aes_ecb.decrypt(C_i)
                P_i_xor_C_0 = xor(P_i_xor_C_0_xor_1336, self.magic)
                P_i = xor(P_i_xor_C_0, C_0)
                # print(f"{C_i.hex()=}, {P_i.hex()=}")
                plaintext += P_i
            else: 
                C_i = ciphertext[i: i+self.block_length]
                P_i_xor_C_i_m1_xor_1336 = self.aes_ecb.decrypt(C_i)
                P_i_xor_C_i_m1 = xor(P_i_xor_C_i_m1_xor_1336, self.magic)
                C_i_m1 = ciphertext[i-self.block_length: i]
                P_i = xor(P_i_xor_C_i_m1, C_i_m1)
                # print(f"{C_i.hex()=}, {P_i.hex()=}")
                plaintext += P_i
        
        if(len(plaintext)):
            plaintext = unpad(plaintext, self.block_length)
        # print(f"AFTER DECRYPT {plaintext.hex()=}, {ciphertext.hex()=}")
        return plaintext


def main():
    cipher = StrangeCBC(get_random_bytes(16))

    # Block-aligned pts
    for i, pt in enumerate([bytes(range(i)) for i in range(0, 256, 16)]):
        # print(f"{pt.hex()=}")
        # c = cipher.encrypt(pt)
        # print(f"{c.hex()=}")
        # d = cipher.decrypt(c)
        # print(f"{d.hex()=}")
        try:
            assert cipher.decrypt(cipher.encrypt(pt)) == pt
        except AssertionError as e:
            print(i, pt.hex(), e)

    # Non-block-aligned pts
    for pt in [bytes(range(i)) for i in range(0, 225, 15)]:
        assert cipher.decrypt(cipher.encrypt(pt)) == pt

    key = bytes.fromhex("5f697180e158141c4e4bdcdc897c549a")
    iv  = bytes.fromhex("89c0d7fef96a38b051cb7ef8203dee1f")
    ct = bytes.fromhex(
            "e7fb4360a175ea07a2d11c4baa8e058d57f52def4c9c5ab"
            "91d7097a065d41a6e527db4f5722e139e8afdcf2b229588"
            "3fd46234ff7b62ad365d1db13bb249721b")
    pt = StrangeCBC(key, iv=iv).decrypt(ct)
    print(pt.decode())
    print("flag{" + SHA1.new(pt).digest().hex() + "}")
    # print(f"{unpad(StrangeCBC(key, iv=iv).decrypt(b''), 16)=}")


if __name__ == "__main__":
    main()
