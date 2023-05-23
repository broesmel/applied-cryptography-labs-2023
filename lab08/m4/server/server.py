#!/usr/bin/env python3
import secrets 

from Crypto.Util.number import bytes_to_long

from boilerplate import CommandServer, on_command

from phonebook import phonebook


class BirthdayInviteServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag 
        self.birthday_invite = f"Hi! I'd like to invite you to my birthday party! You must know the secret password, which by the way is {flag}. Come with a costume: the theme is cryptographic horror! I've heard someone is going to dress up as textbook RSA! xoxo ~Kien".encode()
        print(self.birthday_invite.hex())
        super().__init__(*args, **kwargs)


    def encrypt(self, e: int, N: int, msg: bytes):
        """Encrypts a message using plain RSA""" 
        msg_int = bytes_to_long(msg)
        ctxt = pow(msg_int, e, N)
        return hex(ctxt)[2:]

    @on_command("invite")
    def invite_handler(self, msg):
        """Function to generate the invite for a person""" 
        try:
            invitee = msg["invitee"]
            if invitee not in phonebook:
                self.send_message({"error": "I don't know who that is :("})
                return 
            
            data = phonebook[invitee]
            e, N = data["e"], data["N"]

            ctxt = self.encrypt(e, N, self.birthday_invite)

            self.send_message({
                "message": f"Ok! Can you please give this to {invitee}?",
                "ciphertext": ctxt
            })
        except (KeyError, ValueError, TypeError) as e:
            self.send_message({"error": f"Invalid parameters. {type(e).__name__}: {e}"})



if __name__ == "__main__":
    flag = "flag{test_flag_1}"
    BirthdayInviteServer.start_server('0.0.0.0', 50804, flag=flag)
