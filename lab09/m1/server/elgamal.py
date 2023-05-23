from typing import Tuple

from Crypto.PublicKey import ElGamal

from random import randint

from Crypto.Util.number import bytes_to_long, long_to_bytes


class ElGamalImpl:
    @classmethod
    def decrypt(cls, key: ElGamal.ElGamalKey, c1: bytes, c2: bytes) -> bytes:
        """Your decryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for decryption
            c1 (bytes): first component of an ElGamal ciphertext
            c2 (bytes): second component of an ElGamal ciphertext

        Returns:
            (bytes): the plaintext message
        """

        c1 = bytes_to_long(c1)
        c2 = bytes_to_long(c2)

        # given: 
        # public modulus p
        p = int(key.p)
        # 'primitive element' / generator alpha
        alpha = int(key.g)
        # private key x_B
        x_B = int(key.x)

        # Step 1: recovering K = (alpha^k)^x_B mod p= c1^x_b mod p
        K = pow(c1, x_B, p)

        # Step 2: recovering m by dividing c2 by K: m = c2 * K^-1 mod p 
        m = c2 * pow(K, -1, p) % p

        return long_to_bytes(m)
        


    @classmethod
    def encrypt(cls, key: ElGamal.ElGamalKey, msg: bytes) -> Tuple[bytes, bytes]:
        """Your encryption code goes here.

        Args:
            key (ElGamal.ElGamalKey): the ElGamal key used for encryption
            msg (bytes): the plaintext message to be sent

        Returns:
            (bytes, bytes): c1 and c2 of an ElGamal ciphertext
        """
        # given: 
        # public modulus p
        p = key.p
        # 'primitive element' / generator alpha
        alpha = key.g
        # target public key y
        y_B = key.y

        # message m chosen by A
        m = int.from_bytes(msg, byteorder="big")
        # random number k chosen by A uniformly from {0, ..., p-1}
        # serves as the secret x_A in the key distribution scheme
        k = randint(0, p-1)

        # A computes the "key" K = y_B^k mod p
        K = pow(y_B, k, p)
        # A computes the ciphertext (c1, c2) = (alpha^k mod p, K * m mod p)
        c1 = pow(alpha, k, p)
        c2 = K * m % p

        c1 = long_to_bytes(c1)
        c2 = long_to_bytes(c2)

        return (c1, c2)