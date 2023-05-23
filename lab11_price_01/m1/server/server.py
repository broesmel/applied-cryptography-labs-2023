#!/usr/bin/env python3
import secrets
import json

from boilerplate import CommandServer, on_command

from Crypto.Util.number import long_to_bytes

# this is what you have to implement in this and previous challenge
from eccrypto import ECDSA


CHALLENGE_LENGTH = 64


class ECDSAChallenger(CommandServer):
    def __init__(self, flag: str, *args, **kwargs):
        self.ecdsa = ECDSA()
        self.ecdsa.keygen()
        self.flag = flag
        self.secretBits = None

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
                case "get_challenge":
                    self.send_message(
                        {
                            "public_point": self.ecdsa.public_point.to_bytes(
                                compression=True
                            ).hex(),
                            "challenge": self.get_challenge(),
                        }
                    )
                case "backdoor":
                    self.send_message(
                        {"res": self.get_flag(signed_command["solution"])}
                    )
                case _:
                    self.send_message(
                        {
                            "error": b"The command you tried to execute was not recognized: "
                            + command
                        }
                    )
        except (KeyError, ValueError) as e:
            self.send_message({"error": "Ran into an exception:" + str(e)})

    def get_status(self):
        msg = "Hello there!"
        return msg

    def get_challenge(self):
        """This function is the main component of the challenge.

        Upon the verification of the signature (for "get_challenge"), the client is given
        the public point of the server of its ECDSA instance and CHALLENGE_LENGTH signatures.
        Some of the signatures are incorrect.
        The client has to distinguish the correct ones from the fake ones and return a list of
        True or False in the subsequent query. If the client can succeed in this, he gets the flag.
        """
        if self.secretBits != None:
            return "Challenge was already generated!"

        self.secretBits = []

        challenge = []
        challenge_msgs = [str(ii) for ii in range(CHALLENGE_LENGTH)]
        for challenge_msg in challenge_msgs:
            if secrets.randbelow(1000) < 500:
                signature = self.ecdsa.sign(challenge_msg.encode())
                challenge += [
                    {
                        "msg": challenge_msg,
                        "r": signature[0].hex(),
                        "s": signature[1].hex(),
                    }
                ]
                self.secretBits += [True]

            else:
                r_int = secrets.randbelow(self.ecdsa.ec.n) + 1
                s_int = secrets.randbelow(self.ecdsa.ec.n) + 1
                challenge += [
                    {
                        "msg": challenge_msg,
                        "r": long_to_bytes(r_int).hex(),
                        "s": long_to_bytes(s_int).hex(),
                    }
                ]
                self.secretBits += [False]

        return challenge

    def get_flag(self, solution):
        if self.secretBits != None and solution == self.secretBits:
            return self.flag
        else:
            return "Challenge response is incorrect"


if __name__ == "__main__":
    flag = "flag{test_flag}"
    ECDSAChallenger.start_server("0.0.0.0", 51101, flag=flag)
