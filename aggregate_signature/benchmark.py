""" Performance measurements. """
from benchmark_helper import tester

from lib import setup
from lib import elgamal_keygen
from lib import keygen, sign, aggregate_sign, aggregate_keys, randomize, verify
from lib import prepare_blind_sign, blind_sign, elgamal_dec, prepare_blind_verify, blind_verify
from binascii import hexlify, unhexlify


# ==================================================
# config
# ==================================================
RUNS = 1


# ==================================================
# main -- run the tests
# ==================================================
def main():
	# ----------------------------------------------
	# generate benchmark data
	# ----------------------------------------------
	params = setup()
	(G, o, g1, h1, g2, e) = params

	# user parameters
	m = 5 # message
	(priv, pub) = elgamal_keygen(params) # El Gamal keypair
	
	# generate commitment and encryption for blind signature
	(cm, c, proof_s) = prepare_blind_sign(params, m, pub)

	# signer 1
	(sk1, vk1) = keygen(params)
	blind_sig1 = blind_sign(params, sk1, cm, c, pub, proof_s)
	(h, enc_sig1) = blind_sig1
	sig1 = (h, elgamal_dec(params, priv, enc_sig1))

	# signer 2
	(sk2, vk2) = keygen(params)
	blind_sig2 = blind_sign(params, sk2, cm, c, pub, proof_s)
	(h, enc_sig2) = blind_sig2
	sig2 = (h, elgamal_dec(params, priv, enc_sig2))

	# aggregate signatures
	sig = aggregate_sign(sig1, sig2)

	# randomize signature
	sig = randomize(params, sig)

	# aggregate keys
	vk = aggregate_keys(vk1, vk2)

	# generate kappa and proof of correctness
	(kappa, proof_v) = prepare_blind_verify(params, vk, m)


	# ----------------------------------------------
	# start standard timing benchmarking
	# ----------------------------------------------
	print(""); print("-" * 68)
	print("operations\t\tmean [ms]\t\tsd [ms]\t\truns")
	print("-" * 68)

	# [keygen]
	tester(RUNS, "keygen\t\t", keygen, 
	    params 
	)

	"""
	signature on clear message
	"""
	# [sign]
	tester(RUNS, "sign\t\t", sign, 
	    params, sk1, m 
	)
	# [aggregate_sign]
	tester(RUNS, "aggregate_sign\t", aggregate_sign, 
	    sig1, sig2,
	)
	# [aggregate_keys]
	tester(RUNS, "aggregate_keys\t", aggregate_keys, 
	    vk1, vk2,
	)
	# [randomize]
	tester(RUNS, "randomize_sign\t", randomize, 
	    params, sig,
	)
	# [verify]
	tester(RUNS, "verify\t\t", verify, 
	    params, vk, m, sig
	)

	"""
	signature on hidden message
	"""
	# [prepare_blind_sign]
	tester(RUNS, "prepare_blind_sign", prepare_blind_sign, 
	    params, m, pub
	)
	# [blind_sign]
	tester(RUNS, "blind_sign\t", blind_sign, 
	    params, sk1, cm, c, pub, proof_s
	)
	# [prepare_blind_verify]
	tester(RUNS, "prepare_blind_verify", prepare_blind_verify, 
	    params, vk, m
	)
	# [blind_verify]
	tester(RUNS, "blind_verify\t", blind_verify, 
	    params, vk, kappa, sig, proof_v
	)


	print("-" * 68); print("")


# ==================================================
# entry point
# ==================================================
if __name__ == '__main__':
    main()