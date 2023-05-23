#!/usr/bin/env python3

def blockify(data: bytes, blocksize: int):
    assert(len(data) % blocksize == 0)
    return [int.from_bytes(data[i:i+blocksize], 'big') for i in range(0, len(data), blocksize)]

def left_shift_circular(word: int, shift_amount:int = 1) -> int:
    return ((word << shift_amount) | (word >> (32 - shift_amount))) & 0xffffffff

BLOCK_SIZE_BYTES = 64
WORD_SIZE_BYTES = 4
LONG_SIZE_BYTES = 8

class SHAzam:
    def __init__(self):
        self.hash = [
            0x49276d20,
            0x62756c6c,
            0x65747072,
            0x6f6f6620,
            0x3f213f21
        ]
        self.buffer = b''
        self.length = 0

    def _compress(self, data):
        W = blockify(data, 4)
        W += [0] * (80 - len(W))
        assert(len(W) == 80)
        for t in range(16, 80):
            W[t] = left_shift_circular(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16])

        A, B, C, D, E = self.hash[0], self.hash[1], self.hash[2], self.hash[3], self.hash[4]
        for t in range(0, 80):
            temp = left_shift_circular(A, 5) + self._f(t, B, C, D) + E + W[t] + self._K(t)
            temp &= 0xffffffff
            A, B, C, D, E = temp, A, left_shift_circular(B, 30), C, D

        self.hash[0] = (self.hash[0] + A) & 0xffffffff
        self.hash[1] = (self.hash[1] + B) & 0xffffffff
        self.hash[2] = (self.hash[2] + C) & 0xffffffff
        self.hash[3] = (self.hash[3] + D) & 0xffffffff
        self.hash[4] = (self.hash[4] + E) & 0xffffffff


    def _K(self, t):
        if 0 <= t < 20:
            return 0x5a827999
        elif 20 <= t < 40:
            return 0x6ed9eba1
        elif 40 <= t < 60:
            return 0x8f1bbcdc
        elif 60 <= t < 80:
            return 0xca62c1d6
        else:
            raise ValueError(f"Invalid value for t={t} (Must be 0 <= t < 80)")


    def _f(self, t, B, C, D) -> int:
        if 0 <= t < 20:
            return (B & C) | ((~B) & D)
        elif 20 <= t < 40:
            return B ^ C ^ D
        elif 40 <= t < 60:
            return (B & C) | (B & D) | (C & D)
        elif 60 <= t < 80:
            return B ^ C ^ D
        else:
            raise ValueError(f"Invalid value for t={t} (Must be 0 <= t < 80)")


    def update(self, data: bytes) -> None:
        """Takes `data` and updates the hash state

        This function take bytes as input and appends them to `buffer`. If the length of `buffer` is now greater
        than or equal to BLOCK_SIZE_BYTES, the buffer is split into blocks of size BLOCK_SIZE_BYTES and each full block is processed
        by using the `_compress` function. The last incomplete block (if any) becomes the new value of the buffer.
        If there is no such block, the buffer becomes empty.
        
        The instance member `self.length` helps you to keep track of the number of bytes being processed by the `_compress` function.

        """
        
        self.buffer += data
        self.length += len(data)
        
        while len(self.buffer) >= BLOCK_SIZE_BYTES:
            self._compress(self.buffer[:BLOCK_SIZE_BYTES])
            # self.length += BLOCK_SIZE_BYTES
            self.buffer = self.buffer[BLOCK_SIZE_BYTES:]



    def digest(self):
        """Returns the digest of the data

        This function applies the final padding to the data and extracts the resulting hash.
        For the padding, use the scheme shown here: https://datatracker.ietf.org/doc/html/rfc3174#section-4.
        The length of the message mentioned in the rfc is in bits (not bytes).
        Then, use the update function with the computed padding.
        To extract the hash, take `self.hash` and convert each integer into a 4-byte word. Then, concatenate them to obtain a single
        20-byte string.
        """
        # remainder for encoding the length
        remainder_bytes = (self.length + 8) % 64
        filler_bytes = 64 - remainder_bytes
        zero_bytes = filler_bytes - 1
        encoded_bit_length = (8 * self.length).to_bytes(8, "big")
        padding = b'\x80' + b'\x00' * zero_bytes + encoded_bit_length

        print(f"prior: {b''.join([i.to_bytes(4, 'big') for i in self.hash]).hex()}")
        print(f"prior: {self.buffer=}")
        print(f"{padding.hex()=}")

        self.update(padding)
        print(f"after: {b''.join([i.to_bytes(4, 'big') for i in self.hash]).hex()}")
        print(f"after: {self.buffer=}")

        return b''.join([i.to_bytes(4, 'big') for i in self.hash])

"""As a summary, a "1" followed by m "0"s followed by a 64-
   bit integer are appended to the end of the message to produce a
   padded message of length 512 * n.  The 64-bit integer is the length
   of the original message.  The padded message is then processed by the
   SHA-1 as n 512-bit blocks.


   Suppose a message has length l < 2^64.  Before it is input to the
   SHA-1, the message is padded on the right as follows:

   a. "1" is appended.  Example: if the original message is "01010000",
      this is padded to "010100001".

   b. "0"s are appended.  The number of "0"s will depend on the original
      length of the message.  The last 64 bits of the last 512-bit block
      are reserved

      for the length l of the original message.

      Example:  Suppose the original message is the bit string

         01100001 01100010 01100011 01100100 01100101.

      After step (a) this gives

         01100001 01100010 01100011 01100100 01100101 1.

      Since l = 40, the number of bits in the above is 41 and 407 "0"s
      are appended, making the total now 448.  This gives (in hex)

         61626364 65800000 00000000 00000000
         00000000 00000000 00000000 00000000
         00000000 00000000 00000000 00000000
         00000000 00000000.

   c. Obtain the 2-word representation of l, the number of bits in the
      original message.  If l < 2^32 then the first word is all zeroes.
      Append these two words to the padded message.

      Example: Suppose the original message is as in (b).  Then l = 40
      (note that l is computed before any padding).  The two-word
      representation of 40 is hex 00000000 00000028.  Hence the final
      padded message is hex

         61626364 65800000 00000000 00000000
         00000000 00000000 00000000 00000000
         00000000 00000000 00000000 00000000
         00000000 00000000 00000000 00000028.

      The padded message will contain 16 * n words for some n > 0.
      The padded message is regarded as a sequence of n blocks M(1) ,
      M(2), first characters (or bits) of the message.
"""

if __name__ == "__main__":
    sha = SHAzam()

    # Add assert for compression function
    sha.update(b'DC is better than Marvel anyway!')
    # digest = sha.digest().hex()
    # print(f"{digest=}")
    assert(sha.digest().hex() == '3cd46b5888ee08dc695cd77003e1ebe4cd4d552f')

    sha = SHAzam()
    sha.update(b"I'm sorry Stan Lee, I actually love you please don't hurt me")
    print(f'Your flag is: {sha.digest().hex()}')
