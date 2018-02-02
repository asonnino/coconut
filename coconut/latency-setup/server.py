##########################################
# Server main file
# server.py
#
# version: 0.0.1
##########################################
import sys
# coconut
from lib import setup
from lib import elgamal_keygen
from lib import keygen, sign, aggregate_sign, aggregate_keys, randomize, verify
from lib import prepare_blind_sign, blind_sign, elgamal_dec, show_blind_sign, blind_verify
from lib import ttp_th_keygen, aggregate_th_sign
# petlib import-export
from utils import pack, unpack
# flask
from json  import loads, dumps
from flask import Flask, request
# url parser
from urllib.parse import urlparse



##########################################
# statis fields
server_id = None

# crypto
params = setup()

# make packet for client
def format(load):
	return dumps({
		"status": "OK",  
		"machine_id": server_id,
		"load": load,
	})

##########################################
# server functions
##########################################
def sign_wrapper(data):
	m = data["message"]
	sig = sign(params, app.sk, m)
	return format(pack(sig))

def blind_sign_wrapper(data):
	cm = unpack(data["cm"])
	c = unpack(data["c"])
	proof_s = unpack(data["proof_s"])
	pub = unpack(data["pub"])
	blind_sig = blind_sign(params, app.sk, cm, c, pub, proof_s)
	return format(pack(blind_sig))


##########################################
# webapp
##########################################
app = Flask(__name__)
app.sk = None

# ----------------------------------------
# /sign/public
# return basic info about the server
# ----------------------------------------
@app.route("/", methods=["GET", "POST"])
def index():
	return dumps({"status": "OK"})

# ----------------------------------------
# /key/set
# request a signature on a public attribute
# ----------------------------------------
@app.route("/key/set", methods=["GET", "POST"])
def key_set():
	if request.method == "POST":
		try:
			data = loads(request.data.decode('utf-8'))
			app.sk = unpack(data["sk"])
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
			return sign_wrapper(loads(request.data.decode("utf-8")))
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
			return blind_sign_wrapper(loads(request.data.decode("utf-8")))
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
	port = int(sys.argv[1])
	server_id = port
	app.run(host="0.0.0.0", port=port) 


##########################################

