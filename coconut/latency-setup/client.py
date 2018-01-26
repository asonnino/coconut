##########################################
# Client main file
# client.py
#
# version: 0.0.1
##########################################
# coconut
from lib import setup
from lib import elgamal_keygen
from lib import keygen, sign, aggregate_sign, aggregate_keys, randomize, verify
from lib import prepare_blind_sign, blind_sign, elgamal_dec, show_blind_sign, blind_verify
from lib import ttp_th_keygen, aggregate_th_sign
# petlib import-export
from utils import pack, unpack
# standard REST lib
from json  import loads, dumps
import requests
# async REST lib
import asyncio
import concurrent.futures
import requests
import grequests 
# timing & db
import time
from tinydb import TinyDB, Query


##########################################
# parameters
ATTRIBUTE = 10
N = 3
T = 2

# crypto
params = setup()
(sk, _, vvk) = ttp_th_keygen(params, T, N)

# static fields
PUBLIC_SIGN_DB = 'public_sign.json'
PRIVATE_SIGN_DB = 'private_sign.json'
SERVER_ADDR = ["127.0.0.1"] * 3
SERVER_PORT = [5000+i for i in range(N)]
REPEAT = 10

ROUTE_SERVER_INFO = "/"
ROUTE_KEY_SET = "/key/set"
ROUTE_SIGN_PUBLIC = "/sign/public"
ROUTE_SIGN_PRIVATE = "/sign/private"

# timings
mem = []
tic = 0


##########################################
# utils
##########################################
# test server connection
def test_connection():
    for i in range(N):
        r = requests.get(
            "http://"+SERVER_ADDR[i]+":"+str(SERVER_PORT[i])+ROUTE_SERVER_INFO
        )
        assert loads(r.text)["status"] == "OK"

# response handler
def response_handler(response, *args, **kwargs):
    toc = time.clock()
    record(toc, loads(response.text))

# store data in mem
def record(time, data):
    mem.append({'time':time, 'request':data})

# stave mem to file
def save(filename):
    with open(filename, 'w') as file:
        file.write('[')
        for i in range(len(mem)): 
            mem[i]['time'] = mem[i]['time'] - tic
            file.write(dumps(mem[i]))
            if i != len(mem)-1: file.write(',')
        file.write(']')


##########################################
# test server connection
##########################################
def set_key():
    for i in range(N):
        r = requests.post(
            "http://"+SERVER_ADDR[i]+":"+str(SERVER_PORT[i])+ROUTE_KEY_SET, 
            data = dumps({"sk": pack(sk[i])})
        )
        assert loads(r.text)["status"] == "OK"


##########################################
# request signature
##########################################
def request_sign():
    unsent_request = [
        grequests.post(
            "http://"+SERVER_ADDR[i]+":"+str(SERVER_PORT[i])+ROUTE_SIGN_PUBLIC, 
            hooks={'response': response_handler}, 
            data=dumps({"message":ATTRIBUTE})
        )
        for i in range(N)
    ]
    tic = time.clock()
    responses = grequests.map(unsent_request, size=N)
    for r in responses: assert loads(r.text)["status"] == "OK"


##########################################
# request blind signature
##########################################
def request_blind_sign():
    # TODO
    assert True


##########################################
# main function
##########################################
def main():
    # test server connection
    test_connection()

    # attribute private key to each authority
    set_key()

    # request signature on a public attribute
    del mem[:]
    for _ in range(REPEAT): request_sign()
    save(PUBLIC_SIGN_DB)

    
##########################################
# program entry point
##########################################
if __name__ == "__main__": 
    main()


##########################################