import remote
from Crypto.Hash import SHA256
from string import ascii_letters, digits
from telnetlib import Telnet

def xor(X: bytes, Y: bytes):
    # for i in range(len(X)):
        # c += bytes([X[i] ^ Y[i]])

    return bytes(x ^ y for (x, y) in zip(X, Y))

def pkcs7_p(X: bytes, k: int=0x08):
    lth = len(X)
    if lth % k == 0:
        return X + bytes(k * [k])
    else:
        return X + bytes((k-(lth % k)) * [k-(lth % k)])

def pkcs7_r(X: bytes):
    k = X[-1]
    return X[:-k]

def a0():
    flag_b = b"flag"
    r = pkcs7_p(flag_b, 16)
    print(r.hex())
    print(pkcs7_r(r))

def m0():
    request = {
        "command": "flag",
        "token": "534554454320415354524f4e4f4d59"
    }
    remote.json_send(request)
    response = remote.json_recv()
    print(response)

def m1():
    with open('aes.data', 'r') as aes_data:
        for i, l in enumerate(aes_data):
            c = bytes.fromhex(l)
            c_blocks = []
            for x in range(0, len(c), 16):
                c_blocks.append(c[x:x+16])
            dup = {x for x in c_blocks if c_blocks.count(x) > 1}
            if(len(dup)): print(i, dup)

def m2_1():
    with Telnet("aclabs.ethz.ch", 50220) as remote.tn:
        prepend_pad="00"*128
        request = {
            "command": "encrypt",
            "prepend_pad": prepend_pad,
        }
        remote.json_send(request)
        response1 = remote.json_recv()
        
        prepend_pad=pkcs7_p(b'flag, please!',16).hex()
        prepend_pad= prepend_pad + '00'*(128-len(prepend_pad))
        request['prepend_pad'] = prepend_pad
        remote.json_send(request)
        response2 = remote.json_recv()
        # print(response1['res'])
        # print(response2['res'])
        key = 'e7f1e86909e7315f4b32220a3534d19e' #?
        # print(f'{key=}')
        offset = 0

        enc = response2['res'][:32+offset] # first 16 bytes of our speciallu crafted message
        request = {
            "command": "solve",
            "ciphertext": enc,
        }
        remote.json_send(request)
        response = remote.json_recv()
        print(response)

def m2_2():
    with Telnet("aclabs.ethz.ch", 50221) as tn:
        remote.tn = tn

        for a in range(5):
            try:
                length = 0
                last_length = 0
                for i in range(16):
                    prepend_pad = "00"*i
                    remote.json_send({'command': 'encrypt', 'prepend_pad': prepend_pad})
                    res = remote.json_recv()['res']
                    # print(f"{i:2} - {res}")
                    current_length = len(res)
                    if(current_length > last_length):
                        length = 16-i
                        last_length = current_length
                
                if(length == 0): length = 16

                print(f"{length=}")
                # bruteforce first block
                brutus = ''
                block = 0
                for i in range(15, 16-length-1, -1):
                    prepend_pad = "00"*(i)
                    remote.json_send({'command': 'encrypt', 'prepend_pad': prepend_pad})
                    res_base = remote.json_recv()['res']
                    found=False
                    for x in range(0x7f):
                        prop = bytes([x]).hex()
                        prepend_pad = "00"*(i)+ brutus + prop
                        remote.json_send({'command': 'encrypt', 'prepend_pad': prepend_pad})
                        res_comp = remote.json_recv()['res']
                        # print(f"{res_base[:32]=}\n{res_comp[:32]=}")
                        if(res_base[:32] == res_comp[:32]):
                            brutus += prop
                            found = True
                            break
                    if not found:
                        print('NOTHING FOUND !!!')
                        
                
                print(f"{brutus=}, {len(brutus)=}, {length=}, {bytes.fromhex(brutus).decode()=}, {bytes.fromhex(brutus).decode()[-1]=}")
                remote.json_send({"command": "solve", "solve": bytes.fromhex(brutus).decode()[-1]})
                good = remote.json_recv()
                print(good)
            except EOFError as e:
                print('FAILED, RESTARTING...', e)
                m2_2()
                return
        # done
        remote.json_send({"command": "solve", "solve": bytes.fromhex(brutus).decode()[-1]})
        good = remote.json_recv()
        print('+++ DONE +++')
        print(good)


        return

def m2_3():
    with Telnet("aclabs.ethz.ch", 50222) as remote.tn:
        try:
            length = 0
            last_length = 0
            for i in range(16):
                prepend_pad = "00"*i
                remote.json_send({'command': 'encrypt', 'prepend_pad': prepend_pad})
                res = remote.json_recv()['res']
                # print(f"{i:2} - {res}")
                current_length = len(res)
                if(current_length > last_length):
                    length = 16-i
                    last_length = current_length
            
            if(length == 0): length = 16

            print(f"{length=}")
            # bruteforce first block
            brutus = ''
            blocks = 4
            for i in range(blocks*16-1, -1, -1):
                prepend_pad = "00"*(i)
                remote.json_send({'command': 'encrypt', 'prepend_pad': prepend_pad})
                res_base = remote.json_recv()['res']
                found=False
                for x in range(0x7f):
                    prop = bytes([x]).hex()
                    prepend_pad = "00"*(i)+ brutus + prop
                    remote.json_send({'command': 'encrypt', 'prepend_pad': prepend_pad})
                    res_comp = remote.json_recv()['res']
                    if(res_base[(blocks-1)*32:blocks*32] == res_comp[(blocks-1)*32:blocks*32]):
                        brutus += prop
                        found = True
                        break
                if not found:
                    print('NOTHING FOUND !!!')
            print(f"{brutus=}, {len(brutus)=}, {length=}, {bytes.fromhex(brutus).decode()=}, {bytes.fromhex(brutus).decode()[-1]=}")
        except EOFError as e:
            print('FAILED, RESTARTING...', e)
            m3()
            return
        # done
        remote.json_send({"command": "solve", "solve": bytes.fromhex(brutus).decode()[-1]})
        good = remote.json_recv()
        print('+++ DONE +++')
        print(good)


        return

def m3():
    with open('flag.enc', 'r') as f:
        from Crypto.Hash import SHA256
        from Crypto.Cipher import AES
        flag = f.read()
        print(f"{len(flag)=} {flag=}")
        iv = bytes.fromhex("e764ea639dc187d058554645ed1714d8")
        seed_range = range(0x20, 0x7e)
        key_length = 16
        for s in range(0xFFFF):
            seed = s.to_bytes(2, byteorder='big')
            hash_object = SHA256.new(seed)
            aes_key = hash_object.digest()
            trunc_key = aes_key[:key_length]

            cipher = AES.new(trunc_key, AES.MODE_CBC, iv)
            plaintext = cipher.decrypt(bytes.fromhex(flag))
            try:
                print(plaintext.decode())
            except UnicodeDecodeError:
                continue
        
m2_2()