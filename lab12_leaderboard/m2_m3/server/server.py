#!/usr/bin/env python3
from enum import Enum
from typing import ByteString, Tuple
from dataclasses import dataclass
import zlib
from boilerplate import CommandServer, on_command, on_startup

import gzip
import time
import json
import math
import secrets

from Crypto.PublicKey import ECC
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.number import inverse

"""
A true cryptographer, his prowess renowned,
In cryptographic protocols, vulnerabilities found,
In game-hopping proofs, he finds his delight,
A dance with logic, weaving truths in the night.

Blindfolded, he scripts padding oracles bold,
His fingers glide, secrets to behold,
Abusing side-channels, he bends the unseen,
Crafting defiances, where others demean.

In realms of cryptic depths, where secrets lie,
Where ciphers dance and shadows multiply,
Oh, true cryptographer, thy path divine,
Where knowledge and cunning art intertwine.

~ ChatGPT, 2023
"""

# Every BACKUP_TIME_INTERVAL seconds, the client may try to backup data
BACKUP_TIME_INTERVAL = 600

# Parameters of the NIST P-256 curve
CURVE_NAME = "NIST P-256"
p = 115792089210356248762697446949407573530086143415290314195533631308867097853951
q = 115792089210356248762697446949407573529996955224135760342422259061068512044369
G = ECC.EccPoint(
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

# Size of the counter in bytes in the associated data
COUNTER_SIZE = 32

# The number of bytes required to represent a field element (e.g. a coordinate)
FIELD_ELEM_BYTES = math.ceil(q.bit_length() / 8)


class InvalidStateError(Exception):
    pass


class AKEError(Exception):
    pass


def EccKey_to_bytes(key: ECC.EccKey) -> bytes:
    x = int(key.pointQ.x).to_bytes(FIELD_ELEM_BYTES, "big")
    y = int(key.pointQ.y).to_bytes(FIELD_ELEM_BYTES, "big")
    return x + y


def EccKey_from_bytes(key_bytes: bytes) -> ECC.EccKey:
    x = int.from_bytes(key_bytes[:FIELD_ELEM_BYTES], "big")
    y = int.from_bytes(key_bytes[FIELD_ELEM_BYTES:], "big")
    return ECC.construct(curve=CURVE_NAME, point_x=x, point_y=y)


def ECDSA_sign(msg: bytes, key: ECC.EccKey) -> Tuple[int, int]:
    d = int(key.d)
    h = int.from_bytes(SHA256.new(msg).digest(), "big")

    while True:
        k = secrets.randbelow(q - 1) + 1
        K = G * k
        r = int(K.x) % q

        if r == 0:
            continue

        s = (inverse(k, q) * (h + r * d)) % q

        if s != 0:
            return r, s


def ECDSA_verify(msg: bytes, r: int, s: int, key: ECC.EccKey) -> bool:
    # Bring r, s to the correct range
    r %= q
    s %= q

    h = int.from_bytes(SHA256.new(msg).digest(), "big")
    u1 = (h * inverse(s, q)) % q
    u2 = (r * inverse(s, q)) % q
    P = G * u1 + key.pointQ * u2
    return r == P.x


class BackupStatus(Enum):
    NO_BACKUP = -1
    SUCCESS = 0
    FAILED = 1
    NOT_ACKED = 2


class EigenBackupsClient:
    def __init__(
        self,
        flag1: str,
        flag2: str,
        password: str,
        client_privkey: ECC.EccKey,
        client_pubkey: ECC.EccKey,
        server_pubkey: ECC.EccKey,
    ):
        self.password = password
        self.flag1 = flag1
        self.flag2 = flag2

        self.client_privkey = client_privkey
        self.client_pubkey = client_pubkey
        self.server_pubkey = server_pubkey

        # Initialize master secret
        salt = "all these flavours and you choose to be salty"
        master_secret = scrypt(self.password, salt, 32, N=2**20, r=8, p=1)

        # Derive keys for the two backups from the master secret

        # Backup 1
        self.key_backup1: bytes = HKDF(master_secret, salt=b"", key_len=32, hashmod=SHA256, num_keys=1, context=b"1")  # type: ignore
        # Backup 2
        self.key_backup2: bytes = HKDF(master_secret, salt=b"", key_len=32, hashmod=SHA256, num_keys=1, context=b"2")  # type: ignore

        # Initialize state machine for client's AKE
        # 0 - Initialized, waiting for signal to start AKE
        # 1 - CLIENT_HELLO written, waiting for SERVER_HELLO
        # 2 - SERVER_HELLO received, AKE is concluded
        self.ake_state = 0

        # Messages sent and received, used for associated data so that no re-ordering / replay can happen
        self.counter_read = 0
        self.counter_write = 0

        # Status of last Backup
        self.last_backup_time = None
        self.last_backup_status = BackupStatus.NO_BACKUP

    def ake_initialize(self):
        if self.ake_state != 0:
            raise InvalidStateError("Invalid state in AKE: not in pre-init phase")

        self.eph_privkey = ECC.generate(curve="NIST P-256")
        self.eph_pubkey = self.eph_privkey.public_key()

        pubkey_bytes = EccKey_to_bytes(self.eph_pubkey)
        r, s = ECDSA_sign(pubkey_bytes, self.client_privkey)

        self.ake_state = 1

        return {
            "type": "CLIENT_HELLO",
            "pubkey": pubkey_bytes.hex(),
            "signature": {"r": r, "s": s},
        }

    def ake_server_hello_recv(self, server_hello: dict):
        if self.ake_state != 1:
            raise InvalidStateError(
                "Invalid state in AKE: not in SERVER_HELLO waiting phase"
            )

        pubkey = bytes.fromhex(server_hello["pubkey"])

        r = server_hello["signature"]["r"]
        s = server_hello["signature"]["s"]

        if not ECDSA_verify(pubkey, r, s, self.server_pubkey):
            raise AKEError("Invalid server signature")

        shared_secret_point = EccKey_from_bytes(pubkey).pointQ * int(self.eph_privkey.d)
        shared_secret = int(shared_secret_point.x).to_bytes(FIELD_ELEM_BYTES, "big")

        self.session_key_write: bytes = HKDF(shared_secret, salt=b"", key_len=32, hashmod=SHA256, num_keys=1, context=b"session_client")  # type: ignore
        self.session_key_read: bytes = HKDF(shared_secret, salt=b"", key_len=32, hashmod=SHA256, num_keys=1, context=b"session_server")  # type: ignore

        self.ake_state = 2

    def deliver_client_message(self, message: dict):
        if self.ake_state == 2:
            # We are in transport sub-protocol, read message encrypted under session keys
            # We only accept CREATE_BACKUP and RETURN_CODE messages

            payload = bytes.fromhex(message["payload"])
            tag = bytes.fromhex(message["tag"])
            nonce = bytes.fromhex(message["nonce"])

            session_cipher_read = AES.new(self.session_key_read, AES.MODE_GCM, nonce=nonce)  # type: ignore

            # Add read counter to associated data
            session_cipher_read.update(self.counter_read.to_bytes(COUNTER_SIZE, "big"))

            plaintext = session_cipher_read.decrypt_and_verify(payload, tag)
            msg = json.loads(plaintext.decode())

            self.counter_read += 1

            match msg["type"]:
                case "CREATE_BACKUP":
                    result = self.create_backup(msg["server_metadata"])
                case "RETURN_CODE":
                    result = self.ack_backup(msg["status_code"])
                case _:
                    raise ValueError("Invalid message type")

            session_cipher_write = AES.new(self.session_key_write, AES.MODE_GCM)  # type: ignore

            # Add write counter to associated data
            session_cipher_write.update(
                self.counter_write.to_bytes(COUNTER_SIZE, "big")
            )

            payload_out, tag_out = session_cipher_write.encrypt_and_digest(
                json.dumps(result).encode()
            )

            self.counter_write += 1

            return {
                "payload": payload_out.hex(),
                "tag": tag_out.hex(),
                "nonce": session_cipher_write.nonce.hex(),
            }
        elif self.ake_state == 1:
            # We are in the AKE sub-protocol, we are expecting a server_hello message
            self.ake_server_hello_recv(message)
            return {}
        else:
            # Not expecting any message, so raise error
            raise InvalidStateError("Invalid state: not expecting a message")

    def create_backup(self, server_metadata: str):
        """Mhh... it seems like EigenBackups is using a pull architecture for backups? Very strange..."""

        if self.last_backup_status == BackupStatus.NOT_ACKED:
            return {"result": "Last backup has not been acked"}

        if (
            self.last_backup_time is not None
            and self.last_backup_status == BackupStatus.SUCCESS
            and self.last_backup_time - int(time.time()) < BACKUP_TIME_INTERVAL
        ):
            return {
                "result": "Last backup was succesfully executed less than 10 minutes ago"
            }

        # Split the metadata into a version byte and the remaining metadata
        version = server_metadata[:1]
        metadata = server_metadata[1:]

        backup_content1 = f"metadata={version}&secret={self.flag1}"
        nonce1 = secrets.token_bytes(3)
        backup_cipher1 = AES.new(key=self.key_backup1, mode=AES.MODE_GCM, nonce=nonce1)  # type: ignore

        backup1, tag1 = backup_cipher1.encrypt_and_digest(backup_content1.encode())
        backup_content2_pre = f"{metadata}" + f"{self.flag2}"
        backup_content2 = zlib.compress(
            backup_content2_pre.encode()
        )
        backup_cipher2 = AES.new(key=self.key_backup2, mode=AES.MODE_GCM)  # type: ignore
        backup2, tag2 = backup_cipher2.encrypt_and_digest(backup_content2)

        self.last_backup_status = BackupStatus.NOT_ACKED

        return {
            "type": "STORE_BACKUP",
            "backup1": {
                "nonce": nonce1.hex(),
                "content": backup1.hex(),
                "tag": tag1.hex(),
            },
            "backup2": {
                "nonce": backup_cipher2.nonce.hex(),
                "content": backup2.hex(),
                "tag": tag2.hex(),
            }
        }

    def ack_backup(self, status_code):
        if self.last_backup_status != BackupStatus.NOT_ACKED:
            return {"result": "Last backup has already been acked"}

        if status_code == "FAILURE":
            self.last_backup_status = BackupStatus.FAILED
            return {"result": "ok"}
        elif status_code == "SUCCESS":
            self.last_backup_status = BackupStatus.SUCCESS
            self.last_backup_time = int(time.time())
            return {"result": "ok"}
        else:
            return {"result": "Invalid status code"}


class EigenBackupsServer:
    def __init__(
        self,
        server_privkey: ECC.EccKey,
        server_pubkey: ECC.EccKey,
        client_pubkey: ECC.EccKey,
    ):
        self.server_privkey = server_privkey
        self.server_pubkey = server_pubkey
        self.client_pubkey = client_pubkey
        self.storage = {}

        # Initialize state machine for server's AKE
        # 0 - Initialized, waiting for CLIENT_HELLO
        # 1 - CLIENT_HELLO received, SERVER_HELLO written, AKE is concluded
        self.ake_state = 0

        # Messages sent and received, used for associated data so that no re-ordering / replay can happen
        self.counter_read = 0
        self.counter_write = 0

    def ake_client_hello_recv(self, client_hello: dict):
        if self.ake_state != 0:
            raise InvalidStateError("Invalid state in AKE: not in pre-init phase")

        pubkey = bytes.fromhex(client_hello["pubkey"])
        r = client_hello["signature"]["r"]
        s = client_hello["signature"]["s"]

        if not ECDSA_verify(pubkey, r, s, self.client_pubkey):
            raise AKEError("Invalid client signature")

        self.eph_privkey = ECC.generate(curve="NIST P-256")
        self.eph_pubkey = self.eph_privkey.public_key()

        pubkey_bytes = EccKey_to_bytes(self.eph_pubkey)
        r, s = ECDSA_sign(pubkey_bytes, self.server_privkey)

        shared_secret_point = EccKey_from_bytes(pubkey).pointQ * int(self.eph_privkey.d)
        shared_secret = int(shared_secret_point.x).to_bytes(FIELD_ELEM_BYTES, "big")

        self.session_key_read: bytes = HKDF(shared_secret, salt=b"", key_len=32, hashmod=SHA256, num_keys=1, context=b"session_client")  # type: ignore
        self.session_key_write: bytes = HKDF(shared_secret, salt=b"", key_len=32, hashmod=SHA256, num_keys=1, context=b"session_server")  # type: ignore

        self.ake_state = 1

        return {
            "type": "SERVER_HELLO",
            "pubkey": pubkey_bytes.hex(),
            "signature": {"r": r, "s": s},
        }

    def deliver_server_message(self, message: dict):
        if self.ake_state == 1:
            # We are in transport sub-protocol, read message encrypted under session keys
            # We only accept STORE_BACKUP messages

            nonce = bytes.fromhex(message["nonce"])
            payload = bytes.fromhex(message["payload"])
            tag = bytes.fromhex(message["tag"])

            session_cipher_read = AES.new(self.session_key_read, AES.MODE_GCM, nonce=nonce)  # type: ignore

            # Add read counter to associated data
            session_cipher_read.update(self.counter_read.to_bytes(COUNTER_SIZE, "big"))

            plaintext = session_cipher_read.decrypt_and_verify(payload, tag)
            msg = json.loads(plaintext.decode())

            self.counter_read += 1

            match msg["type"]:
                case "STORE_BACKUP":
                    result = self.store_backup(msg["backup"])
                case _:
                    raise ValueError("Invalid message type")

            session_cipher_write = AES.new(self.session_key_write, AES.MODE_GCM)  # type: ignore

            # Add write counter to associated data
            session_cipher_write.update(
                self.counter_write.to_bytes(COUNTER_SIZE, "big")
            )

            payload_out, tag_out = session_cipher_write.encrypt_and_digest(
                json.dumps(result).encode()
            )

            self.counter_write += 1

            return {
                "payload": payload_out.hex(),
                "tag": tag_out.hex(),
                "nonce": session_cipher_write.nonce.hex(),
            }
        elif self.ake_state == 0:
            # We are in the AKE sub-protocol, we are expecting a client_hello message
            return self.ake_client_hello_recv(message)
        else:
            # Not expecting any message, so raise error
            raise InvalidStateError("Invalid state: not expecting a message")

    def store_backup(self, backup):
        self.backup = backup
        return {"type": "RETURN_CODE", "status_code": "SUCCESS"}


class TrueCryptographerControlPanel(CommandServer):
    """
    EigenBackups is a company specialized in "zero-knowledge backups": they allow you to
    upload your data to their servers, encrypted with your own keys. The CEO claims
    that, because they don't have their clients' keys, they cannot decrypt any of their
    data. Once again, today we shall prove them wrong.

    You have been asked to conduct a security assessment of their infrastructure.
    You will start as a network attacker. From this TrueCryptographerControlPanel
    you can send and intercept messages between the client and the server.
    Your final objective is to recover the contents of the user backups.

    On a high level, the protocol works as follows:
        1. The client and the server execute an authenticated key-exchange to derive symmetric keys
        2. The client and the server will then exchange messages, encrypted with the session key
        3. Every 10 minutes, the client can execute two backups, each of which contains one half of the flag.

    Think outside of the box. Don't be afraid to break the rules.
    Where we're going we don't need rules, only flags.
    """

    def __init__(
        self,
        flag1: str,
        flag2: str,
        password: str,
        client_privkey: ECC.EccKey,
        server_privkey: ECC.EccKey,
        *args,
        **kwargs,
    ):
        client_pubkey = client_privkey.public_key()
        server_pubkey = server_privkey.public_key()

        self.backup_client = EigenBackupsClient(
            flag1, flag2, password, client_privkey, client_pubkey, server_pubkey
        )
        self.backup_server = EigenBackupsServer(
            server_privkey, server_pubkey, client_pubkey
        )
        super().__init__(*args, **kwargs)

    @on_command("start_ake")
    def start_ake(self, msg):
        try:
            res = self.backup_client.ake_initialize()
            self.send_message({"intercepted_payload": res})
        except Exception as e:
            self.send_message({"error": f"Ran into an exception: {e}"})

    @on_command("send_message_to_client")
    def msg_to_client(self, msg):
        try:
            res = self.backup_client.deliver_client_message(msg["message"])
            self.send_message({"intercepted_payload": res})
        except Exception as e:
            self.send_message({"error": f"Ran into an exception: {e}"})

    @on_command("send_message_to_server")
    def msg_to_server(self, msg):
        try:
            res = self.backup_server.deliver_server_message(msg["message"])
            self.send_message({"intercepted_payload": res})
        except Exception as e:
            self.send_message({"error": f"Ran into an exception: {e}"})


if __name__ == "__main__":
    flag1 = "flag{test_flag}"
    flag2 = "flag{4n0th3r_tes7_fl4g}"
    client_password = "my_super_secure_password_with_lots_of_entropy"
    client_privkey = ECC.construct(
        curve="NIST P-256",
        d=29593196296992884452421552910458557080184340494137238015246556634418946311205,
    )
    server_privkey = ECC.construct(
        curve="NIST P-256",
        d=39399532027613100665986869460751701185092435159413377643159063367028086282714,
    )

    import pkg_resources
    assert float(pkg_resources.get_distribution("pycryptodome").version[:4]) <= 3.12, "You don't satisfy our requirements(.txt)"

    TrueCryptographerControlPanel.start_server(
        "0.0.0.0",
        51202,
        flag1=flag1,
        flag2=flag2,
        password=client_password,
        client_privkey=client_privkey,
        server_privkey=server_privkey,
    )
