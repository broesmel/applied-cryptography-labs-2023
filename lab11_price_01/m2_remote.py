import json

from telnetlib import Telnet
from typing import List

from eccrypto import ECDSA

import matplotlib.pyplot as plt

from Crypto.Hash import SHA256
from Crypto.Util.number import bytes_to_long, long_to_bytes

REMOTE = True

ECDSAinstance = ECDSA()
ECDSAinstance.keygen()

"""
 M2: Time to ECDSA
40
ECDSA Interactive Timing Attack

    Welcome to European Cryptocurrency (ECC) AG! You have just been hired by us to implement and test elliptic curve cryptosystems. Your third task is to "debug" the server code.

Yay! Our ECDSA is now online. But somehow the scalar multiplication function scalar_mult() is somehow very slow.

You have been given the permission to profile the code with the get_debug_info command. With get_debug_info, the server returns a message, a signature, and a list of timings (int). The list of timings represents the execution times of each iteration of the double-and-add technique (index increasing) in the scalar multiplication algorithm used in the signature generation algorithm.

Surely you cannot do anything harmful as you do not have direct access to the secret key of the server.
nc aclabs.ethz.ch 51102 

Hints:
It is a good idea to plot the timings.
Is it true that the timing for an iteration will only be small if the corresponding bit is zero?
Pay attention to the special cases of point addition!
"""


def readline(tn: Telnet):
    return tn.read_until(b"\n")


def json_recv(tn: Telnet):
    line = readline(tn)
    return json.loads(line.decode("utf-8"))


def json_send(tn: Telnet, req):
    request = json.dumps(req).encode("utf-8")
    tn.write(request + b"\n")


def signed_json_send(tn: Telnet, req: dict):
    req_str = json.dumps(req)

    public_point_compressed_bytes = ECDSAinstance.public_point.to_bytes(
        compression=True
    )
    signature = ECDSAinstance.sign(req_str.encode())

    obj = {
        "command": "signed_command",
        "signed_command": req,
        "public_point": public_point_compressed_bytes.hex(),
        "r": signature[0].hex(),
        "s": signature[1].hex(),
    }
    json_send(tn, obj)


# Use the following 3 functions to send commands to the server
def get_status(tn: Telnet):
    obj = {"command": "get_status"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_debug_info(tn: Telnet):
    obj = {"command": "get_debug_info"}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res


def get_control(tn: Telnet, d: int):
    obj = {"command": "get_control", "d": d}
    signed_json_send(tn, obj)
    res = json_recv(tn)
    return res

def attack(tn: Telnet):
    """Your attack code goes here."""

    status = get_status(tn)
    print(status)

    r_debug = get_debug_info(tn)
    print(r_debug)
    timings = r_debug["timings"]
    msg = r_debug["msg"].encode()
    r = bytes.fromhex(r_debug["r"])
    r = bytes_to_long(r)
    s = bytes.fromhex(r_debug["s"])
    s = bytes_to_long(s)

    print(timings)
    # Calculate the threshold dynamically
    threshold = (max(timings) + min(timings)) / 2
    # Classify each iteration as "double" or "double-and-add" based on the timing relative to the threshold
    classification = ["double" if timing < threshold else "double-and-add" for timing in timings]
    print(classification)

    # special cases:
    # 1. the timing does not tell us anything about the first iteration,
    #    as adding to the zero point is fast, and doubling 0 is fast
    # 2. if adding two identical points, it's like two doubles in a row

    # plotting...
    iterations = list(range(len(timings)))
    # Plotting the data
    plt.plot(iterations, timings, marker='o', linestyle='-', color='b')

    # Adding labels and title
    plt.xlabel('Iterations')
    plt.ylabel('Timings')
    plt.title('Timings vs Iterations')

    # Formatting x-axis as integers
    plt.xticks(iterations)

    # Adding classification as text annotations
    for i, cls in enumerate(classification):
        plt.annotate(cls, (iterations[i], timings[i]), textcoords="offset points", xytext=(0,10), ha='center')

    # Displaying the plot
    # plt.show()

    k_bits = ''
    for i in range(len(classification)):
        if classification[i] == "double-and-add":
            k_bits += '1'
        else:
            k_bits += '0'
    
    k_bits = k_bits[::-1]
    k = int(k_bits, 2)
    print(k_bits, k)

    k_0 = k
    k_1 = k + 1

    e = bytes_to_long(SHA256.new(msg).digest())
    self = ECDSAinstance

    R_0 = self.ec.G.scalar_mult(k)
    r_0 = R_0.x % self.ec.n
    
    R_1 = self.ec.G.scalar_mult(k_1)
    r_1 = R_1.x % self.ec.n

    print(f"{r-r_0=}, {r-r_1=}")

    if r - r_0 == 0:
        print("k_0 is correct")
        k = k_0
        r = r_0
    elif r - r_1 == 0:
        print("k_1 is correct")
        k = k_1
        r = r_1
    
    
    # s = (pow(k, -1, self.ec.n) * (e + r * self.d)) % self.ec.n
    # to get the private key, we need to solve for d
    d = (s * k - e) * pow(r, -1, self.ec.n) % self.ec.n
    print(f"{d=}")

    # send the command to the server
    r_get_control = get_control(tn, d)
    return r_get_control['res']


if __name__ == "__main__":
    if REMOTE:
        HOSTNAME = "aclabs.ethz.ch"
    else:
        HOSTNAME = "localhost"
    PORT = 51102
    with Telnet(HOSTNAME, PORT) as tn:
        found = 'Nope'
        while found == 'Nope':
            found = attack(tn)
        print(found)
