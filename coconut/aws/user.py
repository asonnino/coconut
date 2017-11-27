""" """
import sys
sys.path.append('../')

from coconut.lib import setup, keygen, aggregate_sign, aggregate_keys, randomize, verify
from bplib.bp import G2Elem, G1Elem

from json  import loads, dumps
from binascii import hexlify, unhexlify
import requests

# ==================================================
# Constants
# ==================================================
SIGNER_PORT = 5000
VERIFIER_PORT = 4000


# ==================================================
# User class
# ==================================================
class User():
	# ----------------------------------------------
	# init
	# ----------------------------------------------
	def __init__(self, signer_addr, verifier_addr):
		self.signer_addr = signer_addr
		self.verifier_addr = verifier_addr +':'+str(VERIFIER_PORT)
		self.params = setup()


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
	# ask signature
	# ----------------------------------------------
	def _ask_signature_single(self, m, signer_url):
		try:
			r = requests.post(signer_url+'/sign', data = dumps(m))
			returns = loads(r.text)['returns']
			sig1 = self._unpackG1(returns[0])
			sig2 = self._unpackG1(returns[1])
			return (sig1, sig2)
		except Exception as e:
			print(e)
			return None

	def ask_signature(self, m, n):
		sigs = []
		for i in range(0,n):
			signer_url = self.signer_addr +':'+ str(SIGNER_PORT+i)
			sigs.append(self._ask_signature_single(m, signer_url))
		return sigs

	# ----------------------------------------------
	# aggregate signatures
	# ----------------------------------------------
	def func_aggregate_sign(self, sigs):
		sig_aggr = sigs[0]
		for i in range(1, len(sigs)):
			sig_aggr = aggregate_sign(sig_aggr, sigs[i])
		return sig_aggr


	# ----------------------------------------------
	# ask verify
	# ----------------------------------------------
	def ask_verify(self, m, sig):
		try:
			(sig1, sig2) = sig
			data = {'message':m, 'signature': (self._pack(sig1),self._pack(sig2))}
			r = requests.post(self.verifier_addr+'/verify', data = dumps(data))
			return loads(r.text)['returns'] == True
		except Exception as e:
			print(e)
			return False



# ==================================================
# main -- simulate the protocol
# ==================================================
def main():
	n = 2
	m = 10
	signer_addr = r'http://127.0.0.1'
	verifier_addr = r'http://127.0.0.1'
	user = User(signer_addr, verifier_addr)

	# ask for signature
	sigs = user.ask_signature(m,n)
	sig = user.func_aggregate_sign(sigs)

	# ask for verification
	print(user.ask_verify(m, sig))



# ==================================================
# entry point
# ==================================================
if __name__ == '__main__':
    main()


