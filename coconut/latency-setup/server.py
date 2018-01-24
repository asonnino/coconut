##########################################
# Server main file
# server.py
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
from flask import Flask, request


##########################################
# static fields
ID = 1
PORT = 5001

# utilities
def pack(x):
    return hexlify(encode(x))

def unpack(x):
    return decode(unhexlify(x))

# crypto
params = setup()
sk = None



##########################################
# server functions
##########################################
def sign_wrapper(data):
	return {"status": "OK"}

def blind_sign_wrapper(data):
	return {"status": "OK"}


##########################################
# webapp
##########################################
app = Flask(__name__)

# ----------------------------------------
# /sign/public
# return basic info about the server
# ----------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
    return dumps({"status": "OK", "port": PORT, "ID": ID})

# ----------------------------------------
# /key/set
# request a signature on a public attribute
# ----------------------------------------
@app.route("/key/set", methods=["GET", "POST"])
def key_set():
	if request.method == "POST":
		try:
			return dumps({"status": "OK"})
		except KeyError as e:
			return dumps({"status": "ERROR", "message": e.args})
		except Exception as e:
			return dumps({"status": "ERROR", "message": e.args})
	else:
		return dumps({"status": "ERROR", "message":"Use POST method."})

# ----------------------------------------
# /sign/public
# request a signature on a public attribute
# ----------------------------------------
@app.route("/sign/public", methods=["GET", "POST"])
def sign_public():
    if request.method == "POST":
        try:
            return dumps(sign_wrapper(loads(request.data.decode("utf-8"))))
        except KeyError as e:
            return dumps({"status": "ERROR", "message": e.args})
        except Exception as e:
            return dumps({"status": "ERROR", "message": e.args})
    else:
        return dumps({"status": "ERROR", "message":"Use POST method."})

# ----------------------------------------
# /sign/private
# request a signature on a private attribute
# ----------------------------------------
@app.route("/sign/private", methods=["GET", "POST"])
def sign_private():
    if request.method == "POST":
        try:
            return dumps(blind_sign_wrapper(loads(request.data.decode("utf-8"))))
        except KeyError as e:
            return dumps({"status": "ERROR", "message": e.args})
        except Exception as e:
            return dumps({"status": "ERROR", "message": e.args})
    else:
        return dumps({"status": "ERROR", "message":"Use POST method."})



##########################################
# program entry point
##########################################
if __name__ == "__main__": 
    app.run(host="127.0.0.1", port=PORT) 


##########################################

