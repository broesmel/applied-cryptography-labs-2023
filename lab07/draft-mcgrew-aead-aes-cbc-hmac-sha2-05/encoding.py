strings = ['a', 'a 23 bytes long string', '64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes64 bytes']


network_byte_order = 'big'

encodings = []

def compute_length_encoding(s: bytes):
    l = len(s) * 8
    AL = l.to_bytes(64//8, network_byte_order, signed=False)
    return AL


for s in strings:
    AL = compute_length_encoding(s.encode())
    encodings += [AL]
    print(AL.hex(), end=', ')