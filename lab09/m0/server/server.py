#!/usr/bin/env python3
import secrets 

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA512
from Crypto.Cipher import AES 

from boilerplate import CommandServer, on_command


#Secure Diffie Hellamn parameters. Large prime p and a generator g of the group. 
p = 138310982169121381747558764122597210619210738340480962702891175829920658207142294773845187946443544844137496731905524601629446808922823844556308145855101223795300091047881311965153195052528173768386853113976906273825086867518698614505991374282596595726359327494708474529010276666804247171201845149294440548867
g = 35347793643784512578718068065261632028252678562130034899045619683131463682036436695569758375859127938206775417680940187580286209291486550218618469437205684892134361929336232961347809792699253935296478773945271149688582261042870357673264003202130096731026762451660209208886854748484875573768029653723060009335


class SecureDiffieHelmanProtocol(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag 
        self.alice_secret = None 
        self.bob_secret = None 

        # Store the shared keys once derivation is done.
        self.bob_shared = None 
        self.alice_shared = None 
        super().__init__(*args, **kwargs)
    
    @on_command("alice_initialisation")
    def initialise_alice(self, msg):
        """Makes Alice initialise a Diffie Hellman key exchange with Bob.
        She will generate a secure private key x, and return you g^x to pass on to Bob"""
        if self.alice_secret == None: #If Alice's key hasn't been initalized, we initialize it now. 
            self.alice_secret = secrets.randbelow(p)
        alice_public = pow(g,self.alice_secret,p)
        self.send_message({"resp":"Hi Bob, I'm Alice. This is my public key","alice_key": alice_public})


    @on_command("bob_initialisation")
    def initialise_bob(self, msg):
        """Initalise the protocol for Bob. He expects you to send him Alice's hello message!"""
        try:
            alice_hello = msg["alice_hello"]
            if alice_hello["resp"] != "Hi Bob, I'm Alice. This is my public key":
                self.send_message({"error":"Bob ignored your message. He says: I don't believe that Alice sent that message"})
                return 
            
            if alice_hello["alice_key"] <= 0 or alice_hello["alice_key"] >= p:
                self.send_message({"error":"Invalid Public Key for Alice"})
                return 

            if self.bob_secret == None: #If k hasn't been initalised, we initalize it now. 
                self.bob_secret = secrets.randbelow(p)
            bob_public = pow(g,self.bob_secret,p)
            # Derive the shared key 
            self.bob_shared = pow(alice_hello["alice_key"],self.bob_secret,p)
            self.send_message({"resp":"Hi Alice, I'm Bob. This is my public key","bob_key": bob_public})
        except (KeyError, ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})


    def out_of_band_verification(self):
        # Verified that alice and bob derived the same keys 
        if self.alice_shared != None and self.bob_shared != None and self.alice_shared == self.bob_shared:
            return True 
        return False 

    @on_command("alice_finished")
    def finish_alice(self, msg):
        """Alice expects the msg to be the hello message sent from Bob.    
        Upon receiving the hello message from Bob, Alice derives a shared key, performs the out of band verification and then encrypts the flag!"""
        try:
            bob_hello = msg["bob_hello"]
            if bob_hello["resp"] != "Hi Alice, I'm Bob. This is my public key":
                self.send_message({"error":"Alice ignored your message. She says: I don't believe that Bob sent that message"})
                return 
            #Alice derives the shared key 
            if self.alice_secret == None:
                self.send_message({"error":"How can I be finished, if I haven't even said Hello?"})
                return 
            if bob_hello["bob_key"] <= 0 or bob_hello["bob_key"] >= p:
                self.send_message({"error":"Invalid Public Key for Bob"})
                return 

            self.alice_shared = pow(bob_hello["bob_key"],self.alice_secret,p)
            if self.out_of_band_verification():
                #Using the shared secret, generate a random key 
                shared_bytes = self.alice_shared.to_bytes(self.alice_shared.bit_length(), 'big')
                secure_key = HKDF(master = shared_bytes, key_len = 32, salt = b'Secure alice and bob protocol', hashmod = SHA512, num_keys = 1)
                cipher = AES.new(secure_key, AES.MODE_CTR)
                encrypted_flag = cipher.encrypt(self.flag.encode())
                self.send_message({"resp":"ok", "encrypted_flag":encrypted_flag.hex(), "nonce":cipher.nonce.hex()})
            else:
                self.alice_secret = None 
                self.alice_shared = None 
                self.bob_shared = None 
                self.alice_shared = None 
                self.send_message({"error":"Alice and Bob derived different keys! Resetting protocol state."})
        except (KeyError, ValueError) as e:
            self.send_message({"error": f"Invalid parameters: {e}"})


if __name__ == "__main__":
    flag = "flag{test_flag_1}"
    SecureDiffieHelmanProtocol.start_server('0.0.0.0', 50900, flag=flag)
