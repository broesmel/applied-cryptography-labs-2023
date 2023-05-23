#!/usr/bin/env python3
import secrets 
from boilerplate import CommandServer, on_command 
from typing import Optional
from shazam import SHAzam

COMMAND_STRING = b'command=hello&arg=world'

class SHAzamServer(CommandServer):
    def __init__(self, flag, *args, **kwargs):
        self.flag = flag 
        self.key = secrets.token_bytes(16)
        super().__init__(*args, **kwargs)

        
    def mac(self, key: bytes, message: bytes) -> bytes:
        print(f"{key.hex()=}, {message=}, {len(key)+len(message)=}")
        h = SHAzam()
        print(f"empty: {b''.join([i.to_bytes(4, 'big') for i in h.hash]).hex()}")
        h.update(key)
        print(f"u key: {b''.join([i.to_bytes(4, 'big') for i in h.hash]).hex()}")
        h.update(message)
        print(f"u msg: {b''.join([i.to_bytes(4, 'big') for i in h.hash]).hex()}")
        
        return h.digest()
    
    @on_command("get_token")
    def token_handler(self,msg):
        mac = self.mac(self.key, COMMAND_STRING).hex()

        # The command_string is hex encoded for... reasons...
        token = {'authenticated_command': COMMAND_STRING.hex(),'mac': mac}
        self.send_message(token)
        
    @on_command("authenticated_command")
    def authenticated_command_handler(self,msg):
        try:
            command = bytes.fromhex(msg["authenticated_command"])
            mac = self.mac(self.key,command).hex()
            if mac != msg['mac']:
                self.send_message({"err": "Invalid MAC"})
                return 
            
            #Split the command string by '&' so we can obtain the various key-value pains
            fragments = command.split(b'&')
            storage = {}
            try:
                for fragment in fragments:
                    #For all fragments, parse it into '{key} = {value} and store that'
                    print(f"{fragment=}")
                    if b'=' in fragment:
                        key, value = fragment.split(b'=',1)
                        storage[key.decode()] = value  #Store the pair
                    else:
                        continue 
            except:
                self.send_message({"err": "Error while decoding JSON"})
                return 
            
            if storage['command'] == b'hello':
                self.send_message({"resp": f"Hello {storage['arg'].decode()}!"})
            elif storage['command'] == b'flag':
                self.send_message({"resp": self.flag})
        except Exception as e:
            self.send_message({"error": f"Invalid parameters: {e}"})

if __name__ == "__main__":
    flag = "flag{test_flag}"
    SHAzamServer.start_server("0.0.0.0", 50602, flag=flag)
