""" """
from aggregate_signature.lib import setup, keygen, aggregate_sign, aggregate_keys, randomize

from json  import loads, dumps
import requests


# ==================================================
# main -- simulate the protocol
# ==================================================
def main():
	#params = setup()
	signer_url = r'http://127.0.0.1:5001/sign'

	# user parameters
	m = 10

	r = requests.post(signer_url, data = dumps(m))
	print(loads(r.text))

	# signer 1
	"""
	(sk1, vk1) = keygen(params)
	sig1 = sign(params, sk1, m)

	# signer 2
	(sk2, vk2) = keygen(params)
	sig2 = sign(params, sk2, m)

	# affregate signatures
	sig = aggregate_sign(sig1, sig2)
	"""

	# randomize signature
	#randomize(params, sig)

	# aggregate keys
	"""
	vk = aggregate_keys(vk1, vk2)

	# verify signature
	assert verify(params, vk, m, sig)
	"""


# ==================================================
# entry point
# ==================================================
if __name__ == '__main__':
    main()