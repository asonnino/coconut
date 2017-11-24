""" """
from co_cosign.lib import setup, aggregate_keys, verify
from bplib.bp import G2Elem, G1Elem

from json  import loads, dumps
from flask import Flask, request
from binascii import hexlify, unhexlify
import requests


# ==================================================
# Constants
# ==================================================
SIGNER_PORT = 5000


# ==================================================
# Verifier class
# ==================================================
class Verifier():
	# ----------------------------------------------
	# init
	# ----------------------------------------------
	def __init__(self, signer_addr, n):
		self.signer_addr = signer_addr
		self.params = setup()

		# get verification key
		keys = self.ask_vk()
		self.vk = self.func_aggregate_keys(keys)

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
	# ask verification key
	# ----------------------------------------------
	def _ask_vk_single(self, signer_url):
		try:
			r = requests.post(signer_url+'/key')
			returns = loads(r.text)['returns']
			a = self._unpackG2(returns[0])
			b = self._unpackG2(returns[1])
			c = self._unpackG2(returns[2])
			return (a, b, c)
		except Exception as e:
			print(e)
			return None

	def ask_vk(self):
		keys = []
		for i in range(0,n):
			signer_url = self.signer_addr +':'+ str(SIGNER_PORT+i)
			keys.append(self._ask_vk_single(signer_url))
		return keys

	# ----------------------------------------------
	# aggreate verification keys
	# ----------------------------------------------
	def func_aggregate_keys(self, keys):
		vk_aggr = keys[0]
		for i in range(1, len(keys)):
			vk_aggr = aggregate_keys(vk_aggr, keys[i])
		return vk_aggr

	# ----------------------------------------------
	# verify signature
	# ----------------------------------------------
	def func_verify(self, requestData):
		data = loads(requestData)
		m, returns = data['message'], data['signature']
		sig1 = self._unpackG1(returns[0])
		sig2 = self._unpackG1(returns[1])
		return verify(self.params, self.vk, m, (sig1,sig2))



# ==================================================
# Webapp
# ==================================================
app = Flask(__name__)

# index
@app.route("/", methods=['GET', 'POST'])
def app_index():
    return dumps({"status": "OK", "message": "Hello, from Verifier!"})


# issue a signature 
@app.route("/verify", methods=["GET", "POST"])
def app_verify():
    if request.method == "POST":
        try:
        	returns = app.verifier.func_verify(request.data)
        	return dumps({"status" : "OK", "returns" : returns})
        except Exception as e:
        	return dumps({"status"  : "ERROR", "message" : e.args})
    else:
    	return dumps({"status": "ERROR", "message":"Use POST method."})




# ==================================================
# entry point
# ==================================================
if __name__ == '__main__':
	# parameters
	n = 2
	signer_addr = r'http://127.0.0.1'

	# run
	app.verifier = Verifier(signer_addr, n)
	app.run(host="127.0.0.1", port="4000") 

