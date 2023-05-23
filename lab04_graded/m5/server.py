import secrets
import json
import re
import sys
from string import ascii_letters, digits
from time import time
from datetime import datetime, timezone
from dataclasses import dataclass
from boilerplate import CommandServer, on_command, on_startup

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

MAX_LEAKS = 255
ALPHABET = ascii_letters + digits


def blockify(s):
    return [s[i : i + 16] for i in range(0, len(s), 16)]


def xor(a: bytes, b: bytes):
    return bytes(x ^ y for x, y in zip(a, b))


class ParsingException(Exception):
    pass


@dataclass
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


class MontoneServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag
        self.leaks = 0
        key = secrets.token_bytes(16)
        self.cipher = AES.new(key, AES.MODE_ECB)
        super().__init__(*args, **kwargs)

    def encrypt(self, msg):
        bs = self.cipher.block_size

        m0 = secrets.token_bytes(bs)
        c0 = secrets.token_bytes(bs)

        msg_blocks = [msg[i : i + bs] for i in range(0, len(msg), bs)]

        out_blocks = []
        m_prev = m0
        c_prev = c0

        for ptxt_block in msg_blocks:
            n = self.cipher.encrypt(xor(ptxt_block, c_prev))
            ctxt_block = xor(n, m_prev)

            m_prev = ptxt_block
            c_prev = ctxt_block

            out_blocks.append(ctxt_block)

        return m0, c0, b"".join(out_blocks)

    def decrypt(self, m0, c0, ctxt):
        bs = self.cipher.block_size
        ctxt_blocks = [ctxt[i : i + bs] for i in range(0, len(ctxt), bs)]

        out_blocks = []
        m_prev = m0
        c_prev = c0

        for ctxt_block in ctxt_blocks:
            n = xor(ctxt_block, m_prev)
            ptxt_block = xor(self.cipher.decrypt(n), c_prev)

            m_prev = ptxt_block
            c_prev = ctxt_block

            out_blocks.append(ptxt_block)

        return b"".join(out_blocks)

    @on_startup()
    def handle_startup(self):
        self.secret_msg = ALPHABET[:16]
        #''.join(secrets.choice(ALPHABET) for _ in range(16))

    @on_command("init")
    def handle_init(self, msg):
        message_metadata = self.secret_msg.encode() # NOTE: one block long
        content = f"Thank you for using Montone messaging services".encode()

        # Get current (UTC-aware) datetime object and remove microseconds so that the
        # timestamp can be safely encoded as an integer rather than a float
        ts = datetime.now(tz=timezone.utc)
        ts.replace(microsecond=0)


        msg = Message(
            1337,
            1729,
            ts,
            1,
            0,
            message_metadata,
            content,
        )
        m0, c0, ctxt = self.encrypt(msg.to_bytes())
        self.send_message({"m0": m0.hex(), "c0": c0.hex(), "ctxt": ctxt.hex()})

    @on_command("metadata_leak")
    def handle_metadata_leak(self, msg):
        if self.leaks > MAX_LEAKS:
            self.send_message({"error": "We're not *that* leaky!"})
            return

        self.leaks += 1
        try:
            m0 = bytes.fromhex(msg["m0"])
            c0 = bytes.fromhex(msg["c0"])
            ctxt = bytes.fromhex(msg["ctxt"])

            ptxt = self.decrypt(m0, c0, ctxt)

            msg = Message.from_bytes(ptxt)

            self.send_message({"metadata": str(msg)})
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})
        except ParsingException as e:
            self.send_message({"error": f"Parsing error: {e}"})

    @on_command("flag")
    def handle_flag(self, msg):
        try:
            secret_message = msg["solve"]
            print(secret_message)
            if secret_message == self.secret_msg:
                self.send_message({"flag": self.flag})
            else:
                self.send_message({"error": "This ain't it chief."})
                self.close_connection()
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})



if __name__ == "__main__":
    flag = "flag{test_asdadflag}"
    MontoneServer.start_server("0.0.0.0", 50405, flag=flag)
