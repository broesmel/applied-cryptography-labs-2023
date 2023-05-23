from Crypto.Util import number
from Crypto.Random import random

import math
import random

"""
Textbook RSA works as follows:

KeyGen(nbits):

    Set e = 65537
    Choose two large primes p and q, such that gcd(e, p-1) = 1, gcd(e, q-1) = 1 and p != q
    Compute N=p * q where N has nbits bits
    Find d such that d * e = 1 (mod Φ(N))
    (N,e) is the public key and (N,d) is the private key

Enc((N,e), m):

    Compute the ciphertext as c = m^e (mod N)

Dec((N,d), c):

    Compute the plaintext as p = c^d (mod N)

""" 


def rsa_key_gen(nbits=2048) -> tuple[tuple[int, int], tuple[int, int], tuple[int, int]]:
    """Generates textbook rsa keys
       p: first prime
       q: second prime
       N: p*q
       e: public part
       d: secret key
    Args:
        nbits (int, optional): RSA security parameter

    Returns:
        (N, e), (N, d), (p, q)
        where
        pk = (N, e)
        sk = (N, d)
        primes = (p, q)
    """
    # public exponent, needs to be larger than 3 to ensure modular reduction for 
    # messages smaller than N**(1/3); otherwise recovery of plaintexts that are
    # known to be smaller becomes simple: taking cube roots using Newton's method
    e = 65537 
    p = -1
    q = -1

    while True:
        # generate two random primes p and q
        n = nbits // 2 # need to be nbits/2 s.t. p*q = N has nbits
        p = number.getPrime(n)
        q = number.getPrime(n)

        # print(f"candidates: {p=}, {q=}")

        # check if gcd(e, p-1) = 1 and gcd(e, q-1) = 1 and p != q
        if math.gcd(e, p-1) == 1 and math.gcd(e, q-1) == 1 and p != q and (p*q).bit_length() == nbits:
            print(f"gcd correct", end=' ')
            break

   
    print(f"found primes: {p=}, {q=}")
    N = p * q
    print(N.bit_length())

    # compute phi(N)
    phi_N = (p-1) * (q-1)

    # find d such that d * e = 1 (mod phi(N))
    d = pow(e, -1, phi_N)

    # return public key, secret key and primes
    pk = (N, e)
    sk = (N, d)
    primes = (p, q)

    return pk, sk, primes


def rsa_enc(pk: tuple[int, int], m: int) -> int:
    """Textbook RSA encryption

    Args:
        pk (int, int): RSA public key tuple
        m (int): the message to encrypt

    Returns:
        int: textbook rsa encryption of m
    """

    N = pk[0]
    e = pk[1]
    c = pow(m, e, N)
    return c


def rsa_dec(sk: tuple[int, int], c: int) -> int:
    """Textbook RSA decryption

    Args:
        sk (int,int): RSA secret key tuple
        c (int): RSA ciphertext

    Returns:
        int: Textbook RSA decryption of c
    """

    N = sk[0]
    d = sk[1]
    m = pow(c, d, N)
    return m

def main():
    print('running rsa_key_gen')
    res = rsa_key_gen()
    print('done')
    print(res)

if __name__ == "__main__":
    #main()
    pass