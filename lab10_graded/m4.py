#!/usr/bin/env python3

# For connection and sending/receiving JSON
import telnetlib
import json

# from the server
from Crypto.Hash import SHAKE256


"""
 M4: Suboptimal - Hard
200
graded interactive

For this challenge, you are once again given an oracle that encrypts and an oracle that decrypts a message using an RSA-based public-key encryption scheme.

The scheme works as described in the previous challenge (which you should have solved before attempting this problem). This time, you will need to implement a full plaintext recovery.

Recover the full value of ptxt_padded to get the flag! Towards this goal, we give you a few hints in the attached pdf.
nc aclabs.ethz.ch 51004
"""

# helper functions accumulated across the previous labs
def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r
def blockify(a, blocksize=16):
    return [a[i : i + blocksize] for i in range(0, len(a), blocksize)]
def readline():
    return tn.read_until(b"\n")
def json_recv():
    line = readline()
    return json.loads(line.decode())
def json_send(req):
    request = json.dumps(req).encode()
    tn.write(request + b"\n")
def snd_rcv(req):
    json_send(req)
    return json_recv()

# connection details
PORT = 51004
loco = 0
host = "aclabs.ethz.ch"
if loco:
    host = "localhost"
tn = telnetlib.Telnet(host, PORT)
    


# from the handout
def ceil(a: int , b: int) -> int:
    # Necessary because of floating point precision loss
    return a // b + (1 if a % b != 0 else 0)

def get_multiplier(m_max: int , m_min: int , N: int , B: int ) -> int:
    tmp = ceil(2 * B, m_max - m_min)
    r = tmp * m_min // N
    alpha = ceil(r * N , m_min )
    return alpha

# constants grabbed from the server code
RSA_KEYLEN = 1024 # 1024-bit modulus
c_len = RSA_KEYLEN // 8
RAND_LEN = 256 # 256-bit of randomness for masking
P_LEN = (RSA_KEYLEN - RAND_LEN - 8) // 8
msg_error_m0 = 'Error: Decryption failed'
msg_error_mr = 'Eror: Decryption failed'
msg_successy = 'Nom, nom, nom... This plaintext tasted nice!'
# as per the handout
def oracle_msb_0(a:int, c: int, e: int, N: int) -> bool:
    # move encryption / exponentiation inside the oracle to make it more readable
    ae = pow(a, e, N) # NEED TO USE pow() TO MAKE IT FAST ENOUGH
    ae_c = ae * c % N
    # send ciphertext to server and get response
    r_c  = snd_rcv({"command": "decrypt", 'ctxt': int.to_bytes(ae_c, c_len, 'big') .hex()})
    # print("ORACLE:", f"{r_c=}"[-26:-21], end='\r')
    if msg_error_m0 in r_c.get('error', ''):
        # if we have error m0, then m_m[0] != 0 
        # => ae * m >= B
        # => ae * m in [B, 2B[
        print("ORACLE: ae * m >= B", end='\r')
        return True
    else: 
        # if we have error mr, then m_m[0] == 0
        # THIS MEANS THAT dec(ae_c) WAS potentially REDUCED MOD N  !!!
        # => ae * m < B
        # => ae * m in [0, B[ 
        print("Oracle: ae * m < B", end='\r')
        return False


# from the server code
def RSA_unpad(m: bytes) -> bytes:
    if m[0] != 0:
        print("0 byte mismatch")

    rand = m[1:1+RAND_LEN//8]
    ptxt_masked = m[1+RAND_LEN//8:]

    rand_hashed = SHAKE256.new(rand).read(P_LEN)
    ptxt_padded = xor(ptxt_masked, rand_hashed)

    for i, b in enumerate(ptxt_padded):
        if b == 1 and all(ch == 0 for ch in ptxt_padded[:i]):
            return ptxt_padded[i+1:]
    else:
        print('rand mismatch')

def main():
    # las vegas style: if we fail, we restart
    restart = True
    while restart:
        restart = False
        # Get the parameters from the server - new ones if computation failed
        params = snd_rcv({"command": "get_params"})
        N = int(params['N'])
        e = int(params['e'])
        print(f"{params=}, {N.bit_length()=}")
        # as per the handout 
        B = pow(2, (RSA_KEYLEN - 8), N) # will not be reduced as N >= 2^1024
        
        r_flag = snd_rcv({"command": "flag"})
        enc_flag = bytes.fromhex(r_flag['flag'])
        c = int.from_bytes(enc_flag, 'big')
        # c == pow(m, e, N)
        # m == pow(c, d, N)
        i = -1

        
        # step 1: find initial bounds for m, and bit-shift value i to use to construct a0
        for i in range(1, RSA_KEYLEN):
            # encrypting 2^i gives us a bit-shift of i bits to the left in m 
            # when multiplied to our c, due to the homomorphic property of RSA
            # so we can use this to find the number of 0 bits before the first
            # 1 bit of the message (including the padding), ported from m3
            bitshift_multiplier = pow(2, i, N)
            if oracle_msb_0(bitshift_multiplier, c, e, N):
                # breaks when
                # bitshift_multiplier*m >= B
                # => bitshift_multiplier*m in [B, 2B[
                # => bitshift_multiplier*m/2 in [B/2, B[
                break
            
        print(f"\n{bitshift_multiplier=}")

        # like in m3, we can use the number of 0 bits to find the length of the message
        flag_length_bits = RSA_KEYLEN - 8 - i + 1 # subtract 8 for the leading 0 byte
        print(f"{flag_length_bits=}, {RSA_KEYLEN-8=}, {i=}")
        
        # initial bounds as per the handout? gives me less accurate results
        # and division by 0 too often
        m_min = pow(2, flag_length_bits - 1, N) # lower incl. bound of the message
        m_max = pow(2, flag_length_bits, N) # upper exclusive bound of the message

        # step 2: find a0 s.t. a0*m >= N incurs a modular reduction
        a0 = bitshift_multiplier//2 * (N+B)//B # initial guess for a0, as per the handout
        # shifting one less than the required shifts to be sure that a0 * m > B
        # if the oracle returns False then we incurred a modular reduction 
        while oracle_msb_0(a0, c, e, N):
            a0 += bitshift_multiplier//2
            # breaks when 
            # modular reduction happened!
            # a0je*c < B
            # => a0*m >= B
            # => a0*m in [N, N+B]

        # better bounds based on the modular reduction in step 2
        m_min = ceil(N, a0)
        m_max = (N+B)//a0

        d = m_max - m_min
        # difference between the bounds: if the difference is 
        # 1, we narrowed it down to a single value with m_min == m !
        while (d > 1):
            d = m_max - m_min
            print(f"{d.bit_length()=}, {m_min=}")
            try:
                # as per the handout:
                # alpha = get_multiplier(m_max, m_min, N, B)
                # but we need the intermediate value r to compute m_mid too
                tmp = ceil(B * 2, d)
                r = tmp * m_min // N
                alpha = ceil(r*N , m_min)
                m_mid = ceil(r*N + B, alpha)
                
                if oracle_msb_0(alpha, c, e, N):
                    # alpha * m >= B
                    # => alpha*m in [B, 2B[
                    # m in [B/alpha, 2B/alpha[ 
                    # increase m_min!
                    m_min = m_mid
                else:
                    # alpha * m < B
                    # => alpha*m in [0, B[
                    # m in [0, B/alpha[
                    # decrease m_max!
                    m_max = m_mid

            except Exception as exc:
                # las vegas style: catch divisions by 0 and retry for a new 
                # encryption of the flag
                print(f"FAILED, {exc=}, retrying!")
                restart = True
                break

        if not restart: # if we didn't fail, we can decrypt the flag
            m = m_min.to_bytes(c_len, 'big') # convert to bytes w the right length
            if(loco): # for debugging, i sent the original message w padding back too
                m_orig = bytes.fromhex(r_flag['m_orig'])
                m_orig_int = int.from_bytes(m_orig, 'big')
                m_min_int = m_min
                print(f"{(m_min_int-m_orig_int).bit_length()=}")
            print(f"{m.hex()=}")
            flag = RSA_unpad(m) # unpad the message using the server's implementation
            print(f"{flag=}")
            return


if __name__ == "__main__":
    main()
