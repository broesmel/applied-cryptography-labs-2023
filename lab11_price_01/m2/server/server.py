#!/usr/bin/env python3
import secrets
import json
import math
from boilerplate import CommandServer, on_command

from Crypto.Hash import SHA256

from eccrypto import ECDSA

TIMINGS_LENGTH = 5000


class ECDSATimingChallenger(CommandServer):
    def __init__(self, flag: str, *args, **kwargs):
        self.ecdsa = ECDSA()
        self.ecdsa.keygen()
        self.flag = flag

        super().__init__(*args, **kwargs)

    @on_command("signed_command")
    def signed_command_handler(self, msg):
        try:
            signed_command = msg["signed_command"]
            public_point_compressed_bytes = bytes.fromhex(msg["public_point"])
            r_bytes = bytes.fromhex(msg["r"])
            s_bytes = bytes.fromhex(msg["s"])

            signed_command_bytes = json.dumps(signed_command).encode()

            if not self.ecdsa.verify(
                signed_command_bytes, r_bytes, s_bytes, public_point_compressed_bytes
            ):
                self.send_message({"res": "Failed to verify command"})
                return

            command = signed_command["command"]

            match command:
                case "get_status":
                    self.send_message({"status": self.get_status()})
                case "get_debug_info":
                    msg_bytes, r_bytes, s_bytes, timings = self.get_timings()
                    self.send_message(
                        {
                            "msg": msg_bytes.decode(),
                            "r": r_bytes.hex(),
                            "s": s_bytes.hex(),
                            "timings": timings,
                        }
                    )
                case "get_control":
                    self.send_message({"res": self.get_control(signed_command["d"])})
                case _:
                    self.send_message(
                        {
                            "error": b"The command you tried to execute was not recognized: "
                            + command
                        }
                    )
        except (KeyError, ValueError) as e:
            self.send_message({"error": "Ran into an exception:" + str(e)})

    def get_status(self) -> str:
        msg = "Hello there!"
        return msg

    def get_timings(self) -> dict:
        """
        This function is the main component of the challenge.
        Upon the verification of the signature (for "get_debug_info"), the client is given
        the timing info (measured with time.time_ns()) of EllipticCurvePoint.scalar_mult_timed() for each iteration of double-and-add.
        Nothing can go wrong with just timings, right?
        """
        timings_list = []

        # The output below will be the nonce used for the signature

        msg_bytes = str(secrets.randbelow(100000) + 1).encode()
        hLen = math.ceil(self.ecdsa.ec.n.bit_length() / 8)
        msg_hash = SHA256.new(msg_bytes).digest()[:hLen]
        msg_hash_int = int.from_bytes(msg_hash, "big")

        for ii in range(TIMINGS_LENGTH):
            r_bytes, s_bytes, timings = self.ecdsa.sign_timed(msg_bytes)
            timings_list.append(timings)

        # Get the average time for each iteration
        timings_avg = [sum(x) / TIMINGS_LENGTH for x in zip(*timings_list)]

        return msg_bytes, r_bytes, s_bytes, timings_avg

    def get_control(self, d) -> str:
        if d == self.ecdsa.d:
            return self.flag
        else:
            return "Nope"


if __name__ == "__main__":
    flag = "flag{test_flag}"
    ECDSATimingChallenger.start_server("0.0.0.0", 51102, flag=flag)
