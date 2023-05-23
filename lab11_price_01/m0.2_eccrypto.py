from __future__ import annotations
from Crypto.PublicKey import ECC

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


if __name__ == '__main__':
    ec = EllipticCurve('secp256k1')
    # print(ec.zero.double())
    # print(ec.zero.add(ec.zero))
    P = ec.point(
        75846746164744654890135940255517930898558248761828110372515351593031589206,
        111050016299123422683254576097053570021272539988346962909266076186510144220920,
    )
    flag = P.scalar_mult(3089855824876182811037223422683254576097053570021)
    # should equal to
    r = Point(6797664738401079993500032048020420187487016626020467949408987205636298574411, 29393079371138059658683656475029497006421030687323960394391845889032119704627)
    print(flag == ec.point(r.x, r.y))
    print(flag)
