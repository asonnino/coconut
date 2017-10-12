""" Performance measurements. """
from benchmark_helper import tester

from lib import setup
from lib import keygen_sign, sign, aggregate, randomize_sign, verify, private_sign
from lib import enc_side
from lib import prove_sign, verify_sign
from binascii import hexlify, unhexlify


# ==================================================
# config
# ==================================================
RUNS = 100


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
	m = 5 				# message
	sk_enc = o.random() # user enc secret key
	
	# generate commitment and encryption
	r = o.random()
	cm = m*g1 + r*h1  	# commitment
	h = G.hashG1(cm.export())	# hash-to-point
	pk_enc = sk_enc*h  			# user enc public key
	(a, b, k) = enc_side(params, pk_enc, m, h)
	c = (a, b)

	# proof of correctness
	proof = prove_sign(params, pk_enc, c, cm, k, r, m)

	# signer 1
	(sk1, pk1) = keygen_sign(params)
	sig1 = private_sign(params, sk1, cm, c, pk_enc, proof)
	#assert verify(params, pk1, m+sk_enc*k, sig1)

	# signer 2
	(sk2, pk2) = keygen_sign(params)
	sig2 = private_sign(params, sk2, cm, c, pk_enc, proof)
	#assert verify(params, pk2, m+sk_enc*k, sig2)

	# aggregate signatures
	sig = aggregate(sig1, sig2)

	# randomize sigature
	sig = randomize_sign(params, sig)

	# verify signature
	(g, X1, Y1) = pk1
	(g, X2, Y2) = pk2
	pk = (g, X1+X2, Y1+Y2)
	#assert verify(params, pk, m+sk_enc*k, sig)


	# ----------------------------------------------
	# start standard timing benchmarking
	# ----------------------------------------------
	print "operation\t\tmean (s)\t\tsd (s)\t\truns"

	# [keygen_sign]
	tester(RUNS, "keygen_sign\t", keygen_sign, 
	    params 
	)

	# [sign]
	tester(RUNS, "sign\t\t", sign, 
	    params,
	    sk1,
	    m 
	)

	# [aggregate]
	tester(RUNS, "aggregate\t", aggregate, 
	    sig1,
	    sig2,
	)

	# [randomize_sign]
	tester(RUNS, "randomize_sign\t", randomize_sign, 
	    params,
	    sig1,
	)

	# [prove_sign]
	tester(RUNS, "prove_sign\t", prove_sign, 
	    params, 
	    pk_enc, 
	    c, 
	    cm, 
	    k, 
	    r, 
	    m
	)

	# [private_sign]
	tester(RUNS, "private_sign\t", private_sign, 
	    params, 
	    sk1, 
	    cm, 
	    c, 
	    pk_enc, 
	    proof
	)

	# [verify]
	tester(RUNS, "verify\t\t", verify, 
	    params,
	    pk,
	    m,
	    sig
	)


# ==================================================
# entry point
# ==================================================
if __name__ == '__main__':
    main()