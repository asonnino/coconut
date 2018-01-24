##########################################
# Client main file
# client.py
#
# version: 0.0.1
##########################################
from lib import setup
from lib import elgamal_keygen
from lib import keygen, sign, aggregate_sign, aggregate_keys, randomize, verify
from lib import prepare_blind_sign, blind_sign, elgamal_dec, show_blind_sign, blind_verify
from lib import ttp_th_keygen, aggregate_th_sign
from lib import mix_keygen, prepare_mix_sign, mix_sign, mix_aggregate_keys, show_mix_sign, mix_verify
from lib import mix_ttp_th_keygen

from petlib.pack import encode, decode
from binascii import hexlify, unhexlify

from json  import loads, dumps
import requests


##########################################
# static fields
SERVER_ADDR = "http://127.0.0.1"
SERVER_PORT = "5001"
ROUTE_SERVER_INFO = "/"
ROUTE_KEY_SET = "/key/set"
ROUTE_SIGN_PUBLIC = "/sign/public"
ROUTE_SIGN_PRIVATE = "/sign/private"

# utilities
def pack(x):
    return hexlify(encode(x))

def unpack(x):
    return decode(unhexlify(x))

# parameters
ATTRIBUTE = 10
N = 3
T = 2

# crypto
params = setup()
#(sk, _, vvk) = ttp_th_keygen(params, T, N)
sk = 10

##########################################
# main function
##########################################
def main():

    # get server info
    r = requests.get(SERVER_ADDR+":"+SERVER_PORT+ROUTE_SERVER_INFO)
    print(r.text)

    # request signature on a public attribute
    r = requests.post(
        SERVER_ADDR+":"+SERVER_PORT+ROUTE_KEY_SET, 
        data = dumps({"sk": sk})
    )
    print(r.text)

    # request signature on a public attribute
    r = requests.post(
        SERVER_ADDR+":"+SERVER_PORT+ROUTE_SIGN_PUBLIC, 
        data = dumps({"message":ATTRIBUTE})
    )
    print(r.text)

    # request signature on a private attribute
    r = requests.post(
        SERVER_ADDR+":"+SERVER_PORT+ROUTE_SIGN_PRIVATE, 
        data = dumps({"message":ATTRIBUTE})
    )
    print(r.text)
    #assert loads(r.text)["status"] == "ERROR"



##########################################
# program entry point
##########################################
if __name__ == "__main__": 
    main()


##########################################