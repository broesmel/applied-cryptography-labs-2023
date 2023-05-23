from string import ascii_letters, digits
from telnetlib import Telnet

import remote
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad
from secrets import token_bytes
from strangecbc import StrangeCBC

def xor(X: bytes, Y: bytes):
    return bytes(x ^ y for (x, y) in zip(X, Y))

def a0():
    with Telnet("aclabs.ethz.ch", 50390) as remote.tn:
        #remote.tn = tn
        request = {
            "command": "hex_command",
            "hex_command": bytes([0xa5]).hex()
        }
        remote.json_send(request)
        response = remote.json_recv()
        print(response)

def m0():
    pass # see strangecbc.py

def m1():
    pass # see strangectr.py
    with Telnet("aclabs.ethz.ch", 50301) as remote.tn:
        request = {
            "command": "encrypted_command",
            "encrypted_command": "01f0ceb3dad5f9cd23293937c893e0ec"
        }
        remote.json_send(request)
        response = remote.json_recv()
        print(response)
        intro_enrypted_hex = '01f0ceb3dad5f9cd23293937c893e0ec'
        block_size = 16
        intro_pad = pad(b'intro', block_size)
        print(len(intro_pad))
        magic = int(1337).to_bytes(block_size, 'big')
        enc_nonce = xor(xor(bytes.fromhex(intro_enrypted_hex), intro_pad), magic)
        pad_flag = pad(b'flag', block_size)
        flag_xor_1337 = xor(pad_flag, magic)
        flag_enc = xor(enc_nonce, flag_xor_1337)

        request = {
            "command": "encrypted_command",
            "encrypted_command": flag_enc.hex()
        }
        remote.json_send(request)
        response = remote.json_recv()
        print(response)

def m2():
    with Telnet("aclabs.ethz.ch", 50302) as remote.tn:
        block_size = 16

        nonce_enc = b''
        for j in range(0, block_size):
            for i in range(0xff):
                msg = (bytes([0]*(16-(j+1)))+bytes([i])+xor(nonce_enc, bytes([j+1]*j))).hex()
                remote.json_send({
                    "command": "encrypted_command",
                    "encrypted_command": msg
                })
                response = remote.json_recv()
                print(f"{j:2d} - {i:3d} - {response['res']} - {msg} - {nonce_enc.hex()}", end='\r')
                if('No') in response['res']:
                    print(f"{j:2d} - {i:3d} - {response['res']} - {msg} - {nonce_enc.hex()}")
                    # C_i = E_k(N || c(i)) xor P_i xor 1337
                    P_i = bytes([j+1])
                    C_i = bytes([i])
                    nonce_enc = xor(C_i, P_i) + nonce_enc # j+1 j +2 i FUCK
                    break

        print(f"{nonce_enc.hex()=} ALREADY INCLUDES THE MAGIC NUMBER XORED INTO IT. NO NEED TO ADD IT AGAIN.")

        
        pad_flag = pad(b'flag', block_size)

        request = {
            "command": "encrypted_command",
            "encrypted_command": xor(pad_flag, nonce_enc).hex()
        }
        remote.json_send(request)
        response = remote.json_recv()
        print(response)
        return

def m3():
    with Telnet("aclabs.ethz.ch", 50303) as remote.tn:
        remote.json_send({
            "command": "howto",
            "encrypted_command": ""
        })
        response = remote.json_recv()
        print(response)
        intro_enrypted_hex = response['res'].split(': ')[-1]
        remote.json_send({
            "command": "encrypted_command",
            "encrypted_command": intro_enrypted_hex
        })
        response = remote.json_recv()
        print(response)
        block_size = 16
        magic = int(1336).to_bytes(block_size, 'big')

        iv = bytes.fromhex(intro_enrypted_hex)[:block_size]
        enc_intro = bytes.fromhex(intro_enrypted_hex)[block_size:]
        pad_intro = pad(b'intro', block_size)
        print(f"{iv.hex()=}")

        pad_flag = pad(b'flag', block_size)

        # C1 = E(P1 ⊕ IV)
        # Cn = E(Pn ⊕ Cn-1) — for all n > 1
        # P1 = D(C1) ⊕ IV
        # Pn = D(Cn) ⊕ Cn-1 - for all n > 1

        # we received:
        # C1 = IV
        # C2 = E(pad(intro) ⊕ IV)
        # with 
        # P1 = IV
        # P2 = D(C2) ⊕ C1 = pad(intro)

        # since we know P1 and P2 in this case, 
        # we can easily modify C1 and send the following:
        # C1 = IV ⊕ pad(intro) ⊕ pad(flag)
        # C2

        # which leads to the following decryption:
        # P2 = D(C2) ⊕ C1
        #    = pad(intro) ⊕ IV ⊕ (IV ⊕ pad(intro) ⊕ pad(flag))
        #    = pad(flag)


        remote.json_send({
            "command": "encrypted_command",
            "encrypted_command": (xor(xor(iv, pad_flag), pad_intro)+enc_intro).hex()
        })
        
        response = remote.json_recv()

        print(response)
        return

def m4():
    with Telnet("aclabs.ethz.ch", 50340) as remote.tn:
        block_size = 16
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": bytes([0]*16).hex()}))
        print(r:=remote.snd_rcv({"command": "guess", "guess": True}))

        for i in range(299):
                print(
                    r:=remote.snd_rcv(
                        {"command": "decrypt", 
                         "ciphertext": token_bytes(16).hex()} # iv only - zero length input cannot be unpadded :) trivially error
                    )['res']
                , end='\r')
                print(r:=remote.snd_rcv({"command": "guess", "guess": True}))
        
        print(r:=remote.snd_rcv({"command": "flag"}))

def m4_1():
    with Telnet("aclabs.ethz.ch", 50341) as remote.tn:
        block_size = 16
        print('challenge', challenge:=remote.snd_rcv({"command": "challenge"})['res'])
        iv_cl = bytes.fromhex(challenge)[:block_size]
        chlng = bytes.fromhex(challenge)[block_size:]
        print('challenge iv_cl', iv_cl.hex())
        print('challenge chlng',chlng.hex())
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": challenge}))


        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": r['res']}))
        c0 = bytes.fromhex(r['res'])
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": (iv_cl[:15]+chlng).hex()})) # dec_error
        c1 = bytes.fromhex(r['res'])
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": (iv_cl).hex()})) # pad_error
        c2 = bytes.fromhex(r['res'])
        len_all_goood = len(c0) # 32
        len_pad_error = len(c1) # 64
        len_dec_error = len(c2) # 96
        print(f"{len_all_goood=} {len_pad_error=} {len_dec_error=}")

        m = pad(b'Hello!', block_size)
        # attack:
        # we send IV ⊕ C1' ⊕ C2
        # we receive if C2 has valid padding, if yes, the last byte is:
        # D(C2) ⊕ C1' = 0x01 
        # => D(C2) = C1' ⊕ 0x01
        for i in range(100):
            brute=b''
            challenge=remote.snd_rcv({"command": "challenge"})['res']
            iv_cl = bytes.fromhex(challenge)[:block_size]
            chlng = bytes.fromhex(challenge)[block_size:]
            for i in range(0xff):
                r=remote.snd_rcv({"command": "decrypt", "ciphertext": (xor(iv_cl, bytes([0]*15+[i])) + chlng).hex()})
                if(len(bytes.fromhex(r['res'])) == len_dec_error):
                    print(f"{i:2x} - DEC ERROR: {r['res']}", end='\r')
                elif(len(bytes.fromhex(r['res'])) == len_pad_error):
                    print(f"{i:2x} - PAD ERROR: {r['res']}", end="\r")
                elif(len(bytes.fromhex(r['res'])) == len_all_goood):
                    print(f"{i:2x} - VALID PADDING: {r['res']}")
                    brute = xor(iv_cl, bytes([0]*15+[i]))[-1:]
                    break   

            print(brute)
            guess = xor(bytes([0x01]), xor(brute[-1:], iv_cl[-1:]))

            print(r:=remote.snd_rcv({"command": "guess", "guess": guess.decode()}))
        
        print(r:=remote.snd_rcv({"command": "flag"}))
        return


def padding_oracle_CBC(b1, b2, block_size, padding_ok, cmd, tag):
    brute = b''
    for i in range(block_size):
        if not len(brute) == i:
            print("ERRORED")
            break
        for x in range(0xff):
            b1_mod = b1[:-(i+1)]+bytes([x]) + xor(brute, bytes([i+1]*i)) 
            r=remote.snd_rcv({"command": cmd, 
                tag: ( b1_mod
                     + b2
                     ).hex()
            })
            if(len(bytes.fromhex(r['res'])) == padding_ok):
                print(f"{x:2x} - VALID PADDING: {r['res'][:0x40]}...")
                brute = xor(
                    bytes([i+1]), 
                    bytes([x])
                    ) + brute
                break
            else:
                print(f"{x:2x} - PAD/DEC ERROR: {r['res'][:0x40]}...", end="\r")

        print(brute)
    
    guess = xor(brute, b1)
    return guess


def m4_2():
    with Telnet("aclabs.ethz.ch", 50342) as remote.tn:
        block_size = 16
        print('challenge', challenge:=remote.snd_rcv({"command": "challenge"})['res'])
        iv_cl = bytes.fromhex(challenge)[:block_size]
        chlng = bytes.fromhex(challenge)[block_size:]
        print('challenge iv_cl', iv_cl.hex())
        print('challenge chlng',chlng.hex())
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": (iv_cl+chlng).hex()}))
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": challenge}))


        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": r['res']})) # all good /
        c0 = bytes.fromhex(r['res'])
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": (iv_cl[:15]+chlng).hex()})) # dec_error
        c1 = bytes.fromhex(r['res'])
        print(r:=remote.snd_rcv({"command": "decrypt", "ciphertext": (xor(iv_cl, b'0'*15+b'1')+chlng).hex()})) # pad_error
        c2 = bytes.fromhex(r['res'])
        len_all_goood = len(c0) # 32
        len_pad_error = len(c1) # 64
        len_dec_error = len(c2) # 96
        print(f"{len_all_goood=} {len_pad_error=} {len_dec_error=}")

        m = pad(b'Hello!', block_size)
        # attack:
        # we send IV ⊕ C1' ⊕ C2
        # we receive if C2 has valid padding, if yes, the last byte is:
        # D(C2) ⊕ C1' = 0x01 
        # => D(C2) = C1' ⊕ 0x01

        i = 0
        for j in range(10):
            brute=b''
            challenge=remote.snd_rcv({"command": "challenge"})['res']
            iv_cl = bytes.fromhex(challenge)[:block_size]
            chlng = bytes.fromhex(challenge)[block_size:]
            guess = padding_oracle_CBC(iv_cl, chlng, block_size, len_all_goood, "decrypt", "ciphertext")
            print(f"{guess=}")
            
            print(r:=remote.snd_rcv({"command": "guess", "guess": guess.decode()}))
        
        print(r:=remote.snd_rcv({"command": "flag"}))
        return


def m4_3():
    with Telnet("aclabs.ethz.ch", 50343) as remote.tn:
        block_size = 16

        print(r:=remote.snd_rcv({"command": "encrypted_command", "encrypted_command": bytes([0]*16).hex()})) # pad_error
        c0 = bytes.fromhex(r['res'])

        print(r:=remote.snd_rcv({"command": "encrypted_command", "encrypted_command": (c0).hex()})) # no_such_command_error
        c1 = bytes.fromhex(r['res'])

        len_pad_error = len(c0) # 80
        len_noc_error = len(c1) # 144
        len_dec_error = 64
        noc_intro = repr(ValueError(f"No such command. But here's a flag for you: ")).encode()
        len_noc_intro = len(noc_intro)
        len_flag_pad = len_noc_error - len_noc_intro - block_size
        print(f"{len_dec_error=} {len_pad_error=} {len_noc_error=} {len_noc_intro=} {len_flag_pad=}")


        IV_C = c1[ :-2*block_size]
        CN_1 = c1[-2*block_size:-block_size]
        CN_2=  c1[-block_size: ]
        print(f"{c1.hex()} \n {IV_C.hex()=} {CN_1.hex()=} {CN_2.hex()=}")
        print(r:=remote.snd_rcv({"command": "encrypted_command", "encrypted_command": (IV_C+CN_1+CN_2).hex()})) # no_such_command_error

        i = 0
        brute=b''

        blocks = [c1[i:i+block_size] for i in range(0, len(c1), block_size)]
        # # hihi get the server to evaluate ls
        # chosen = pad(b'ls', block_size)
        # block_1_dec = b'ValueError("No s'
        # print(r:=remote.snd_rcv({"command": "encrypted_command", "encrypted_command": (xor(xor(blocks[0], chosen), block_1_dec)+blocks[1]).hex()})) 
        # c2 = bytes.fromhex(r['res'])
        # blocks = [c2[i:i+block_size] for i in range(0, len(c2), block_size)]
        # # decrypts to:
        # # b"['__pycache__', 'secret.py', 'requirements.txt', 'boilerplate.py', 'server.py', 'well_done_if_you_are_reading_this_tell_us_but_no_flag_here']\x05\x05\x05\x05\x05"

        for i in range(len(blocks)-1):
            iv = blocks[i]
            ct = blocks[i+1]
            guess = padding_oracle_CBC(iv, ct, block_size, len_noc_error, "encrypted_command", "encrypted_command")
            print(guess)
            brute += guess
        print(brute)
        # flag{You did not expect the flag to span a single block, did you?}
        

        return

m4_3()