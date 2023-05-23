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



tn = telnetlib.Telnet("aclabs.ethz.ch", 50405)


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
They say that leaking metadata isn't that bad. Today we shall prove them wrong.

The server implements a messaging application, with message serialization and deserialization. Messages are encrypted using AES in IGE mode. You are given a "metadata" oracle that leaks sender, receiver and other values. The oracle accepts up to 128 queries (even failed ones count!). Find a way to recover the secret message, which is in the additional_metadata field of the message. If you manage to do so, you obtain the flag.

The init command returns an AES-IGE encrypted message composed of a fixed protocol header, a metadata block and a single additional_metadata block, which contains the secret message.
The metadata_leak command takes an encrypted message, decrypts it and, if parsing succeeds, leaks some metadata fields of the message: sender, receiver, timestamp and protocol version (but not the additional_metadata).
The flag command takes a guess for the secret message. If the guess is correct, it returns the flag. Otherwise, it closes the connection.
nc aclabs.ethz.ch 50405
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
    ALPHABET = digits + ascii_letters
    ALPHABET_BYTES = set([d.encode() for d in ALPHABET])
    block_size = 16
    message_metadata = bytes([0] * 16) # NOTE: one block long, padded!
    content = f"Thank you for using Montone messaging services".encode()
    
    ts = datetime.now(tz=timezone.utc)
    ts.replace(microsecond=0)
    msg_instance = Message(
        sender=1337,   # 4 bytes
        receiver=1729, # 4 bytes
        timestamp=ts,  # 4 bytes
        proto_maj_version = 1, # 2 bytes
        proto_min_version = 0, # 1 byte
        # metadata length: 1 byte
        additional_metadata=message_metadata, # (0-255 blocks)
        content=content, # no limit
    )
    print(f"{msg_instance=}")
    msg = msg_instance.to_bytes()
    msg_blocks = blockify(msg)
    ptxt_blocks = msg_blocks
    print(msg_blocks, len(msg_blocks))

    print(r0:= snd_rcv({"command": "init"}))
    ctxt = bytes.fromhex(r0['ctxt'])
    m0 = bytes.fromhex(r0['m0'])
    c0 = bytes.fromhex(r0['c0'])

    ctxt_blocks = blockify(ctxt)
    print(ctxt_blocks, len(ctxt_blocks))

    # IGE mode decryption works like this:
    # msg_blocks[0] = D(ctxt_blocks[0] xor m0) xor c0
    # msg_blocks[i] = D(ctxt_blocks[i] xor msg_blocks[i-1]) xor ctxt_blocks[i-1]
    # encryption
    # ctxt_blocks[0] = E(msg_blocks[0] xor c0) xor m0
    # ctxt_blocks[i] = E(msg_blocks[i] xor ctxt_blocks[i-1]) xor msg_blocks[i-1]

    # msg_blocks[0] = D(ctxt_blocks[0] xor m0) xor c0
    # msg_blocks[1] = D(ctxt_blocks[1] xor msg_blocks[0]) xor ctxt_blocks[0]
    # msg_blocks[2] = D(ctxt_blocks[2] xor msg_blocks[1]) xor ctxt_blocks[1]

    

    print(r1 := snd_rcv({"command": "metadata_leak", "ctxt": ctxt.hex(), "m0": m0.hex(), "c0": (c0).hex()}))

    # looking for the flag
    # we know msg_blocks 0, 1, FLAG, 3, 4, 5, 6

    # b'MONTONE-PROTOCOL' = D(ctxt_blocks[0] xor m0) xor c0
    # msg_blocks[1] = D(ctxt_blocks[1] xor b'MONTONE-PROTOCOL') xor ctxt_blocks[0]
    # message_metadata = D(ctxt_blocks[2] xor msg_blocks[1]) xor ctxt_blocks[1]

    # make metadata the second block
    # Capital C for ctxt_blocks, lower case c for c0
    # message_metadata = D(C2 xor M1) xor C1 = D2 xor C1
    # ctxt_b_2 = ctxt_blocks[2] xor msg_blocks[1] xor msg_blocks[0]
    # C2_mod = C2 xor M1 xor M0
    # D2_mod = D((C2_mod) xor M0) xor C0
    # D2_mod = D((C2 xor M1 xor M0) xor M0) xor C0
    # D2_mod = D(C2 xor M1) xor C0
    # D2_mod = D2 xor C0
    # message_metadata = D2_mod xor C1 xor C0

    message_metadata = b''

    potential_last_mm_i = []
    for i in range(0x100):
        last_byte = bytes([i ^ ctxt_blocks[1][-1] ^ ctxt_blocks[0][-1]])
        if last_byte in ALPHABET_BYTES:
            potential_last_mm_i += [i]
    
    # no worries about 128 query limit
    print(f"{len(potential_last_mm_i)} == {len(ALPHABET)=}")
    curr_i = 2
    prev_i = curr_i - 1
    c2_mod = xor(ctxt_blocks[curr_i], msg_blocks[prev_i], msg_blocks[0])

    for last_mm_i in potential_last_mm_i:
        
        ctxt_mod = ctxt_blocks[0] + c2_mod
        ctxt_mod += bytes([0]*16)*last_mm_i

        print(r1 := snd_rcv({"command": "metadata_leak", "ctxt": ctxt_mod.hex(), "m0": m0.hex(), "c0": (c0).hex()}), end='\r')

        res = r1.get('metadata', False)

        if res:
            last_byte = bytes([last_mm_i ^ ctxt_blocks[prev_i][-1] ^ ctxt_blocks[0][-1]])
            res = Message.parse_repr(r1['metadata'])
            
            mm_xor_C1_xor_C0 = b''
            for r in res:
                mm_xor_C1_xor_C0 += r
            
            mm_first_15 = xor(mm_xor_C1_xor_C0, ctxt_blocks[prev_i], ctxt_blocks[0])

            message_metadata = mm_first_15 + last_byte

            break

    print(message_metadata)
    print(r:= snd_rcv({"command": "flag", "solve": message_metadata.decode()}))

    return

main()