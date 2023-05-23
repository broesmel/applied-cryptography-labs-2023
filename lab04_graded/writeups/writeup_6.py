#!/usr/bin/env python3
# from https://cryptohack.org/challenges/introduction/

import telnetlib
import json

from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

import secrets

from string import ascii_letters, digits
from datetime import datetime, timezone
import re

def xor(X: bytes, Y: bytes, *args):
    r = bytes(x ^ y for (x, y) in zip(X, Y))
    for a in args:
        r = xor(r, a)
    return r

def blockify(a, blocksize=16):
    return [a[i : i + blocksize] for i in range(0, len(a), blocksize)]



tn = telnetlib.Telnet("aclabs.ethz.ch", 50406)


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

"""
Expand on your solution for M5.

Again, you are given a "metadata" oracle that leaks sender, receiver and other values, accepting up to 196 queries.

The flag command now returns AES-IGE encrypted message, with the flag in the content field of the message.

nc aclabs.ethz.ch 50406
"""    

class ParsingException(Exception):
    pass

class Message:
    """This class represents a message in the MONTONE protocol

    To create a new instance of this class either use the constructor:

    `Message(sender=0, receiver=1, timestamp=..., proto_maj_version=1, proto_min_version=0, additional_metadata=b'', content=b'')`

    or, alternatively, by deserializing a byte stream with the `from_bytes` class method.
    """

    sender: int
    receiver: int
    timestamp: datetime
    proto_maj_version: int
    proto_min_version: int
    additional_metadata: bytes
    content: bytes

    def __init__(self, sender: int, receiver: int, timestamp: datetime, proto_maj_version: int, proto_min_version: int, additional_metadata: bytes, content: bytes):
        self.sender = sender
        self.receiver = receiver
        self.timestamp = timestamp
        self.proto_maj_version = proto_maj_version
        self.proto_min_version = proto_min_version
        self.additional_metadata = additional_metadata
        self.content = content
        

    @classmethod
    def from_bytes(cls, stream) -> "Message":
        """Implements deserialization of a byte stream into a Message

        Checks the first block for the protocol constant, then parses the metadata in the second block.
        Raises a ParsingException if parsing fails.
        """

        if len(stream) < 32:
            raise ParsingException("Message is too small")

        # First block must be our specific protocol header
        proto_header = stream[:16]
        if proto_header != b"MONTONE-PROTOCOL":
            raise ParsingException("Incorrect header (Protocol Mismatch?)")

        # Second block contains some metadata information
        metadata = stream[16:32]

        sender = int.from_bytes(metadata[:4], "little")
        receiver = int.from_bytes(metadata[4:8], "little")
        timestamp = datetime.fromtimestamp(int.from_bytes(metadata[8:12], "little"), tz=timezone.utc)
        protocol_maj_version = int.from_bytes(metadata[12:14], "little")
        protocol_min_version = metadata[14]

        # Represents the amount of blocks of additional metadata that we have to parse
        additional_metadata_len = metadata[15]
        remaining_stream = stream[32:]

        if additional_metadata_len * 16 > len(remaining_stream):
            raise ParsingException("Not enough blocks for parsing additional metadata")

        additional_metadata = remaining_stream[: additional_metadata_len * 16]
        content = remaining_stream[additional_metadata_len * 16 :]

        return cls(
            sender,
            receiver,
            timestamp,
            protocol_maj_version,
            protocol_min_version,
            additional_metadata,
            content,
        )

    def to_bytes(self) -> bytes:
        """Implements serialization of a Message into bytes"""

        proto_header = b"MONTONE-PROTOCOL"
        sender = self.sender.to_bytes(4, "little")
        receiver = self.receiver.to_bytes(4, "little")
        timestamp = int(self.timestamp.timestamp()).to_bytes(4, "little")
        proto_maj_version = self.proto_maj_version.to_bytes(2, "little")
        proto_min_version = self.proto_min_version.to_bytes(1, "little")

        if len(self.additional_metadata) > 0:
            additional_metadata = pad(self.additional_metadata, 16)
        else:
            additional_metadata = self.additional_metadata

        content = pad(self.content, 16)

        additional_metadata_len = (len(additional_metadata) // 16).to_bytes(1, "little")

        b = (
            proto_header
            + sender
            + receiver
            + timestamp
            + proto_maj_version
            + proto_min_version
            + additional_metadata_len
            + additional_metadata
            + content
        )
        return b

    def __repr__(self):
        """Creates a string representation of the Message, containing the metadata"""

        return (
            f"Montone Protocol (v{self.proto_maj_version}.{self.proto_min_version}) message "
            + f"from {self.sender} to {self.receiver}, sent on {self.timestamp.isoformat()}."
        )

    @staticmethod
    def parse_repr(metadata):
        """Parses a string representation of a Message, returning the metadata fields"""

        majv, minv, src, rcv, ts = re.match(
            r"Montone Protocol \(v(\d+)\.(\d+)\) message from (\d+) to (\d+), sent on (.+)\.",
            metadata,
        ).groups()

        majv = int(majv).to_bytes(2, "little")
        minv = int(minv).to_bytes(1, "little")
        src = int(src).to_bytes(4, "little")
        rcv = int(rcv).to_bytes(4, "little")
        ts = int(datetime.fromisoformat(ts).timestamp()).to_bytes(4, "little")
        return src, rcv, ts, majv, minv

def main():
    # from the server code:
    # ECB mode encryption extended by the IGE mode
    block_size = 16
    test_flag = ""
    message_metadata = b"message_type=flag&lab=4&graded=True"
    content = f"Thank you for using Montone messaging services. Here is a flag that you will not be able to obtain: {test_flag}".encode()

    ts = datetime.now(tz=timezone.utc)
    ts.replace(microsecond=0)
    msg_instance = Message(
        1337,   # sender:           4 bytes
        1729,   # receiver:         4 bytes
        ts,     # timestamp:        4 bytes
        1,      # protocol major v: 2 bytes
        0,      # protocol minor v: 1 byte
        message_metadata, # metadata_len (1 byte) + metadata (0-255 blocks)
        content, # no limit
    )
    print(f"{msg_instance=}")
    msg = msg_instance.to_bytes()
    msg_blocks = blockify(msg)
    print(msg_blocks, len(msg_blocks))

    print(r0:= snd_rcv({"command": "flag"}))
    ctxt = bytes.fromhex(r0['ctxt'])
    m0 = bytes.fromhex(r0['m0'])
    c0 = bytes.fromhex(r0['c0'])

    ctxt_blocks = blockify(ctxt)
    print(ctxt_blocks, len(ctxt_blocks))

    len_flag_blocks = len(ctxt_blocks)+1 - len(msg_blocks)

    # IGE mode decryption works like this:
    # msg_blocks[0] = D(ctxt_blocks[0] xor m0) xor c0
    # msg_blocks[i] = D(ctxt_blocks[i] xor msg_blocks[i-1]) xor ctxt_blocks[i-1]
    # encryption
    # ctxt_blocks[0] = E(msg_blocks[0] xor c0) xor m0
    # ctxt_blocks[i] = E(msg_blocks[i] xor ctxt_blocks[i-1]) xor msg_blocks[i-1]    

    print(r1 := snd_rcv({"command": "metadata_leak", "ctxt": ctxt.hex(), "m0": m0.hex(), "c0": (c0).hex()}))

    # looking for the flag stored in content: from block 5 on, flag from byte 4 in block 11 on
    # we know msg_blocks 0, ..., 10

    # b'MONTONE-PROTOCOL' = D(ctxt_blocks[0] xor m0) xor c0
    # msg_blocks[1] = D(ctxt_blocks[1] xor b'MONTONE-PROTOCOL') xor ctxt_blocks[0]
    # msg_blocks[2] = D(ctxt_blocks[2] xor msg_blocks[1]) xor ctxt_blocks[1]

    # make block 11 the second block
    # msg_blocks[11] = D(C11 xor M10) xor C10 = D11 xor C10
    # C11 = ctxt_blocks[11] xor msg_blocks[10] xor msg_blocks[0]
    # C11_mod = C11 xor M10 xor M0
    # D11_mod = D((C11_mod) xor M10) xor C0
    # D11_mod = D((C11 xor M1 xor M10) xor M10) xor C0
    # D11_mod = D(C11 xor M1) xor C0
    # D11_mod = D11 xor C0
    # msg_blocks[11] = D11_mod xor C10 xor C0

    # to then iterate over to block 12:



    # ptxt_blocks[11] = D(ctxt_blocks[11] xor ptxt_blocks[10]) xor ctxt_blocks[10]

    flag = b''


    print(len_flag_blocks)
    for b in range(len_flag_blocks):
        curr_i = 11 + b
        prev_i = curr_i - 1

        new_metadata = b''
        # same solution as last time, BUT
        c11_mod = xor(ctxt_blocks[curr_i], msg_blocks[prev_i], msg_blocks[0])

        # no assumptions on the exact contents of the flag. to not run out of
        # queries, we use a binary search to find the last byte 

        low = 0
        x = 0
        high = 0x100

        ctxt_mod = ctxt_blocks[0] + c11_mod
        last_byte = bytes([x ^ ctxt_blocks[prev_i][-1] ^ ctxt_blocks[0][-1]])
        r_good = snd_rcv({
                        "command": "metadata_leak", 
                        "ctxt": ctxt_mod.hex(), "m0": m0.hex(), "c0": (c0).hex()
            })
        
        while (low < high) :
            x = low + (high - low) // 2

            ctxt_mod = ctxt_blocks[0] + c11_mod
            ctxt_mod += bytes([0]*16)*x
            r1 = snd_rcv({
                        "command": "metadata_leak", 
                        "ctxt": ctxt_mod.hex(), "m0": m0.hex(), "c0": (c0).hex()
            })
            res = r1.get('metadata', False)
            
            if not res: # x < target: look for larger x
                low = x + 1
            else: # x >= target: remember this and look for smaller x
                high = x
                last_byte = bytes([x ^ ctxt_blocks[prev_i][-1] ^ ctxt_blocks[0][-1]])
                r_good = r1
        # loop ends when low == high => a precise result is found

        print(f"{low=}  {x=} {high=}")

        try:
            r_bytes = Message.parse_repr(r_good['metadata'])
        except KeyError as e:
            print(e, x)
            ctxt_mod = ctxt_blocks[0] + c11_mod
            ctxt_mod += bytes([0]*16)*x
            r1 = snd_rcv({
                        "command": "metadata_leak", 
                        "ctxt": ctxt_mod.hex(), "m0": m0.hex(), "c0": (c0).hex()
            })
            try:
                r_bytes = Message.parse_repr(r1['metadata'])
            except KeyError as e:
                print("no metadata found")
                r_bytes = b''

        mm_xor_Cprev_xor_C0 = b''
        for r in r_bytes:
            mm_xor_Cprev_xor_C0 += r
        
        mm_first_15 = xor(mm_xor_Cprev_xor_C0, ctxt_blocks[prev_i], ctxt_blocks[0])

        new_metadata = mm_first_15 + last_byte

        print(new_metadata)
        if b == 0:
            msg_blocks = msg_blocks[:-1] + [new_metadata]
            flag = new_metadata
        else:
            msg_blocks += [new_metadata]
            flag += new_metadata
            # print(msg_blocks[10:])
        

    flag = flag[4:]
    print(flag)
    return

main()