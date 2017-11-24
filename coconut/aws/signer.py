""" """
from co_cosign.lib import setup, keygen, sign
from bplib.bp import G2Elem, G1Elem

from json  import loads, dumps
from flask import Flask, request
from binascii import hexlify, unhexlify
import sys



# ==================================================
# Signer class
# ==================================================
class Signer():
	# ----------------------------------------------
	# init
	# ----------------------------------------------
	def __init__(self):
		self.params = setup()
		(self.sk, self.vk) = keygen(self.params)

	# ----------------------------------------------
	# pack/unpack EC point
	# ----------------------------------------------
	def _pack(self, elem):
		return hexlify(elem.export()).decode()

	def _unpackG1(self, elem):
		G = self.params[0]
		return G1Elem.from_bytes(unhexlify(elem.encode()), G)

	def _unpackG2(self, elem):
		G = self.params[0]
		return G2Elem.from_bytes(unhexlify(elem.encode()), G)

	# ----------------------------------------------
	# sign
	# ----------------------------------------------
	def issue_signature(self, requestData):
		m = loads(requestData)
		sig1, sig2 = sign(self.params, self.sk, m)
		return (self._pack(sig1), self._pack(sig2))

	# ----------------------------------------------
	# send verification key
	# ----------------------------------------------
	def send_vk(self):
		(a, b, c) = self.vk
		return (self._pack(a), self._pack(b), self._pack(c))




# ==================================================
# Webapp
# ==================================================
app = Flask(__name__)


# index
@app.route("/", methods=['GET', 'POST'])
def app_index():
    return dumps({"status": "OK", "message": "Hello, from Signer!"})

# issue a signature 
@app.route("/sign", methods=["GET", "POST"])
def app_sign():
    if request.method == "POST":
        try:
        	returns = app.signer.issue_signature(request.data)
        	return dumps({"status" : "OK", "returns" : returns})
        except Exception as e:
        	print(e)
        	return dumps({"status"  : "ERROR", "message" : e.args})
    else:
    	return dumps({"status": "ERROR", "message":"Use POST method."})

# send verification key
@app.route("/key", methods=["GET", "POST"])
def app_key():
    if request.method == "POST":
        try:
        	returns = app.signer.send_vk()
        	return dumps({"status" : "OK", "returns" : returns})
        except Exception as e:
        	print(e)
        	return dumps({"status"  : "ERROR", "message" : e.args})
    else:
    	return dumps({"status": "ERROR", "message":"Use POST method."})



# ==================================================
# entry point
# ==================================================
if __name__ == '__main__':
	port = sys.argv[1]
	app.signer = Signer()
	app.run(host="127.0.0.1", port=port) 

