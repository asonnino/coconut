""" tests """
from lib import setup
from lib import keygen_sign, sign, aggregate, randomize_sign, verify, private_sign
from lib import enc_side
from lib import prove_sign, verify_sign


# ==================================================
# test --  sign
# ==================================================
def test_sign():
	params = setup()

	# user parameters
	m = 10

	# signer 1
	(sk1, pk1) = keygen_sign(params)
	sig1 = sign(params, sk1, m)

	# signer 2
	(sk2, pk2) = keygen_sign(params)
	sig2 = sign(params, sk2, m)

	# affregate signatures
	sig = aggregate(sig1, sig2)

	# randomize
	randomize_sign(params,sig)

	# verify signature
	(g, X1, Y1) = pk1
	(g, X2, Y2) = pk2
	pk = (g, X1+X2, Y1+Y2)
	assert verify(params, pk, m, sig)


# ==================================================
# test -- zk proofs (debug)
# ==================================================
"""
def test_proofs():
	params = setup()
	(G, o, g1, h1, g2, e) = params

	m = 5 
	r = o.random()
	cm = m*g1 + r*h1
	h = G.hashG1(cm.export())
	sk_enc = o.random()
	pk_enc = sk_enc*h
	(a, b, k) = enc_side(params, pk_enc, m, h)
	ciphertext = (a, b)

	proof = prove_sign(params, pk_enc, ciphertext, cm, k, r, m)
	assert verify_sign(params, pk_enc, ciphertext, cm, proof)
"""


# ==================================================
# test -- private sign
# ==================================================
def test_private_sign():
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
	assert verify(params, pk1, m+sk_enc*k, sig1)

	# signer 2
	(sk2, pk2) = keygen_sign(params)
	sig2 = private_sign(params, sk2, cm, c, pk_enc, proof)
	assert verify(params, pk2, m+sk_enc*k, sig2)

	# aggregate signatures
	sig = aggregate(sig1, sig2)

	# randomize sigature
	sig = randomize_sign(params, sig)

	# verify signature
	(g, X1, Y1) = pk1
	(g, X2, Y2) = pk2
	pk = (g, X1+X2, Y1+Y2)
	assert verify(params, pk, m+sk_enc*k, sig)


# ==================================================
# test -- n private signature 
# ==================================================
def test_multi_sign():
	params = setup()
	n = 10 # number of signers

	# user parameters
	m = 10

	# generate signer keys
	signer_keys = []
	for i in range(0,n):
		signer_keys.append(keygen_sign(params))

	# aggregate signer keys
	(g, X_aggr, Y_aggr) = signer_keys[0][1]
	for i in range(1,n):
		(g, X, Y) = signer_keys[i][1]
		(g, X_aggr, Y_aggr) = (g, X_aggr+X , Y_aggr+Y)


	""" test on AWS from here """

	# generate signatures
	sig = []
	for i in range(0,n):
		sig.append( sign(params, signer_keys[i][0], m) )
		#assert verify(params, pk1, m+sk_enc*k, sig1)

	# aggregate signatures
	sig_aggr = sig[0]
	for i in range(1,n):	
		sig_aggr = aggregate(sig_aggr, sig[i])

	# randomize sigature
	sig_aggr = randomize_sign(params, sig_aggr)

	# verify signature
	pk = (g, X_aggr, Y_aggr)
	assert verify(params, pk, m, sig_aggr)


# ==================================================
# test -- n signature 
# ==================================================
def test_multi_private_sign():
	params = setup()
	(G, o, g1, h1, g2, e) = params
	n = 10 # number of signers

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

	# generate signer keys
	signer_keys = []
	for i in range(0,n):
		signer_keys.append(keygen_sign(params))

	# aggregate signer keys
	(g, X_aggr, Y_aggr) = signer_keys[0][1]
	for i in range(1,n):
		(g, X, Y) = signer_keys[i][1]
		(g, X_aggr, Y_aggr) = (g, X_aggr+X , Y_aggr+Y)


	""" test on AWS from here """

	# generate private signature
	sig = []
	for i in range(0,n):
		sig.append( private_sign(params, signer_keys[i][0], cm, c, pk_enc, proof) )
		#assert verify(params, pk1, m+sk_enc*k, sig1)

	# aggregate signatures
	sig_aggr = sig[0]
	for i in range(1,n):	
		sig_aggr = aggregate(sig_aggr, sig[i])

	# randomize sigature
	sig_aggr = randomize_sign(params, sig_aggr)

	# verify signature
	pk = (g, X_aggr, Y_aggr)
	assert verify(params, pk, m+sk_enc*k, sig_aggr)
	




