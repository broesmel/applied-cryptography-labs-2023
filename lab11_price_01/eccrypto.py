from __future__ import annotations

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Hash import SHA256
from typing import Tuple

from modsqrt import modular_sqrt

from random import randint

DEFAULT_CURVE_NAME = "secp256k1"


class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return self.x == other.x and self.y == other.y
        return False


class EllipticCurve:
    CurveList = {
        "secp256k1": {
            "p": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
            "a": 0x0000000000000000000000000000000000000000000000000000000000000000,
            "b": 0x0000000000000000000000000000000000000000000000000000000000000007,
            "G": (
                0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
                0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
            ),
            "n": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141,
            "h": 0x1,
        },
        "secp256r1": {
            "p": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF,
            "a": 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC,
            "b": 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B,
            "G": (
                0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
            ),
            "n": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
            "h": 0x1,
        },
    }

    def __init__(self, curve_name):
        self.curve_name = curve_name
        assert curve_name in self.CurveList
        curve = self.CurveList[curve_name]
        self.G = EllipticCurvePoint(self, curve["G"][0], curve["G"][1])
        self.p = curve["p"]
        self.n = curve["n"]
        self.a = curve["a"]
        self.b = curve["b"]
        self.zero = EllipticCurvePoint(self, 0, 0)

    def point(self, x, y) -> EllipticCurvePoint:
        return EllipticCurvePoint(self, x, y)


class EllipticCurvePoint(Point):
    def __init__(self, curve: EllipticCurve, x, y):
        self.curve = curve
        super().__init__(x, y)

    def __eq__(self, other):
        if isinstance(other, EllipticCurvePoint):
            return super(EllipticCurvePoint, self).__eq__(other)
        return False

    def __repr__(self):
        return f"Point({self.x}, {self.y})"


    def double(self) -> EllipticCurvePoint:
        if self == self.curve.zero:
            R = self.curve.zero
        else:
            l = (3 * self.x * self.x + self.curve.a) * pow(2 * self.y, -1, self.curve.p)
            x = (l * l - self.x - self.x) % self.curve.p
            y = (l * (self.x - x) - self.y) % self.curve.p
            R = EllipticCurvePoint(self.curve, x, y)
        return R

    def add(self, Q: EllipticCurvePoint) -> EllipticCurvePoint:
        if self == self.curve.zero:
            R = Q
        elif Q == self.curve.zero:
            R = self
        elif self.x == Q.x:
            R = self.double()
        else:
            l = (Q.y - self.y) * pow(Q.x - self.x, -1, self.curve.p)
            x = (l * l - self.x - Q.x) % self.curve.p
            y = (l * (self.x - x) - self.y) % self.curve.p
            R = EllipticCurvePoint(self.curve, x, y)
        return R

    def scalar_mult(self, n: int) -> EllipticCurvePoint:
        Q = self.curve.zero
        P = self
        while n > 0:
            if n & 1:
                Q = Q.add(P)
            P = P.double()
            n >>= 1
        return Q

    def to_bytes(self, compression: bool = False) -> bytes:
        bytesize = 32
        if compression:
            if self.y & 1:
                return b'\x03' + long_to_bytes(self.x, bytesize)
            else:
                return b'\x02' + long_to_bytes(self.x, bytesize)
        else:
            return b'\x04' + long_to_bytes(self.x, bytesize) + long_to_bytes(self.y, bytesize)

    @staticmethod
    def from_bytes(curve: EllipticCurve, bs: bytes) -> EllipticCurvePoint:
        bytesize = 32
        if bs[0] == 0x04:
            x = bytes_to_long(bs[1 : 1+bytesize])
            y = bytes_to_long(bs[1+bytesize : 1+2*bytesize])
        elif bs[0] == 0x03: # y is odd
            x = bytes_to_long(bs[1 : 1+bytesize])
            # y^{2}=x^{3}+ax+b
            y_square = (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p
            y = modular_sqrt(y_square, curve.p)
            if y & 1 == 0: # computed y is even
                y = curve.p - y # use the other root
            
        elif bs[0] == 0x02: # y is even
            x = bytes_to_long(bs[1 : 1+bytesize])
            # y^{2}=x^{3}+ax+b
            y_square = (pow(x, 3, curve.p) + curve.a * x + curve.b) % curve.p
            y = modular_sqrt(y_square, curve.p)
            if y & 1 != 0: # computed y is odd
                y = curve.p - y # use the other root

        else:
            raise Exception("Invalid format")
        return EllipticCurvePoint(curve, x, y)


class ECDSA:
    def __init__(self, curve_name: str = DEFAULT_CURVE_NAME):
        self.ec = EllipticCurve(curve_name)
        self.d = None
        self.public_point = None

    def keygen(self):
        self.d = randint(1, self.ec.n - 1)
        self.public_point = self.ec.G.scalar_mult(self.d)

    # please use SHA256 as the hash function
    def sign(self, msg_bytes: bytes) -> Tuple[bytes, bytes]:
        e = bytes_to_long(SHA256.new(msg_bytes).digest())
        # 2. z = leftmost Ln bits of e with Ln = ec.n.bit_length() 
        # use z below instead of e
        # breaks on the server, so we use e instead
        r = 0
        s = 0
        while r == 0 or s == 0:
            k = randint(1, self.ec.n - 1)
            R = self.ec.G.scalar_mult(k)
            r = R.x % self.ec.n
            if r == 0:
                continue
            s = (pow(k, -1, self.ec.n) * (e + r * self.d)) % self.ec.n
            if s == 0:
                continue
        
        return (long_to_bytes(r, 32), long_to_bytes(s, 32))
            
    def sign_timed(self, msg_bytes: bytes) -> Tuple[bytes, bytes, list[int]]:
        raise NotImplementedError

    # public_point_bytes can be in both compressed and de-compressed form, need to check
    def verify(
        self,
        msg_bytes: bytes,
        r_bytes: bytes,
        s_bytes: bytes,
        public_point_bytes: bytes,
    ) -> bool:
        Q = EllipticCurvePoint.from_bytes(self.ec, public_point_bytes)
        r = bytes_to_long(r_bytes)
        s = bytes_to_long(s_bytes)

        # print(f"{Q==self.ec.zero=}, {r < 1 =} {r>self.ec.n-1=}, {s < 1 =} {s > self.ec.n-1=}")

        if Q == self.ec.zero or r < 1 or r > self.ec.n - 1 or s < 1: #  or s > self.ec.n - 1:
            print ("Invalid input")
            return False
        
        e = bytes_to_long(SHA256.new(msg_bytes).digest())
        # 3. z = leftmost Ln bits of e with Ln = ec.n.bit_length() 
        # then we would use z below instead of e, but Ln==256 as ec.n.bit_length()==256
        s_inv = pow(s, -1, self.ec.n)
        u1 = (e * s_inv) % self.ec.n
        u2 = (r * s_inv) % self.ec.n
        R = self.ec.G.scalar_mult(u1).add(Q.scalar_mult(u2))
        if R == self.ec.zero:
            return False
        return R.x % self.ec.n == r


