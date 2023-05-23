#!/usr/bin/env python3
import subprocess
import codecs

from boilerplate import CommandServer, on_command, on_startup


class HashPumpServer(CommandServer):
    @on_command("hashpump")
    def pump_handler(self, msg):
        try:
            mac = msg["mac"]
            data = msg["data"]
            append = msg["append"]

            # o = subprocess.check_output(
            #     f"/app/hashpump -s {mac} -d {data} -a {append} -k 16", shell=True
            # )
            o = subprocess.check_output(
                ["/app/hashpump", "-s", mac, "-d", data, "-a", append, "-k", "16"]
            )
            o = o.split(b"\n")

            self.send_message(
                {
                    "new_hash": o[0].decode(),
                    "new_data": codecs.escape_decode(o[1])[0].hex(),
                }
            )
        except Exception as e:
            self.send_message({"error": f"Invalid parameters: {e}"})


if __name__ == "__main__":
    HashPumpServer.start_server("0.0.0.0", 50690)
    print("Flag, ", "5261aaeb518b62677baafb99033389579e10e0dcea7739c3c7f36e322e83f532")