from bplib.bp import BpGroup
from hashlib  import sha256
from binascii import hexlify, unhexlify
from petlib.bn import Bn


# ==================================================
# setup
# ==================================================
def setup():
	""" generate all public parameters """
	G = BpGroup()
	g1, g2 = G.gen1(), G.gen2()
	h1 = G.gen1()
	e, o = G.pair, G.order()
	return (G, o, g1, h1, g2, e)



# ==================================================
# El Gamal encryption scheme
# ==================================================
def elgamal_keygen(params):
   """ generate an El Gamal key pair """
   (G, o, g1, h1, g2, e) = params
   priv = o.random()
   pub = priv * g1
   return (priv, pub)

def elgamal_enc(params, pub, m, h):
    """ encrypts the values of a message h^m """
    (G, o, g1, h1, g2, e) = params
    k = o.random()
    a = k * g1
    b = k * pub + m * h
    return (a, b, k)

def elgamal_dec(params, priv, c):
    """ decrypts the message h^m """
    (G, o, g1, h1, g2, e) = params
    (a, b) = c
    return b - priv*a



# ==================================================
# aggregated signature
# ==================================================
"""
signature on clear message
"""
def keygen(params):
	""" generate a key pair for signature """
	(G, o, g1, h1, g2, e) = params
	(x, y) = o.random(), o.random()
	sk = (x, y)
	vk = (g2, x*g2, y*g2)
	return (sk, vk)

def sign(params, sk, m):
	""" sign a clear message """
	(G, o, g1, h1, g2, e) = params
	(x, y) = sk
	h = G.hashG1((m*g1).export())
	sig = (x+y*m) * h
	return (h, sig)

def aggregate_sign(sig1, sig2):
	""" aggregate signatures """
	sig11 , sig12 = sig1
	sig21 , sig22 = sig2
	assert sig11 == sig21
	return (sig11, sig12+sig22)

def aggregate_keys(vk1, vk2):
	""" aggregate signers verification keys """
	(g2, X1, Y1) = vk1
	(g2, X2, Y2) = vk2
	return (g2, X1+X2, Y1+Y2)

def randomize(params, sig):
	""" randomize signature (after aggregation) """
	(G, o, g1, h1, g2, e) = params
	sig1 , sig2 = sig
	t = o.random()
	return ( t*sig1 , t*sig2 )

def verify(params, vk, m, sig):
	""" verify a signature on a clear message """
	(G, o, g1, h1, g2, e) = params
	(g2, X, Y) = vk
	sig1 , sig2 = sig
	return not sig1.isinf() and e(sig1, X + m * Y) == e(sig2, g2)


"""
signature on hidden message
"""
def prepare_blind_sign(params, m, pub):
	""" build elements for blind sign """
	(G, o, g1, h1, g2, e) = params
	# build commitment
	r = o.random()
	cm = m*g1 + r*h1 
	# build El Gamal encryption
	h = G.hashG1(cm.export()) 
	(a, b, k) = elgamal_enc(params, pub, m, h)
	c = (a, b)
	# proof of correctness
	proof = prove_sign(params, pub, c, cm, k, r, m)
	return (cm, c, proof)

def blind_sign(params, sk, cm, c, pub, proof):
	""" blindly sign a message """
	(G, o, g1, h1, g2, e) = params
	(x, y) = sk
	(a, b) = c
	# verify proof of correctness
	assert verify_sign(params, pub, c, cm, proof)
	# issue signature
	h = G.hashG1(cm.export())
	enc_sig = (y*a, x*h + y*b)
	return (h, enc_sig)

def prepare_blind_verify(params, vk, m):
	""" build elements for blind verify """
	(G, o, g1, h1, g2, e) = params
	(g2, X, Y) = vk
	kappa = X + m*Y
	proof = prove_show(params, vk, m)
	return (kappa, proof)

def blind_verify(params, vk, kappa, sig, proof):
	""" verify a signature on a clear message """
	(G, o, g1, h1, g2, e) = params
	(g2, X, Y) = vk
	sig1 , sig2 = sig
	return not sig1.isinf() \
		and verify_show(params, vk, kappa, proof) \
		and e(sig1, kappa) == e(sig2, g2)



# ==================================================
# zero-knowledge proofs
# ==================================================
def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)


"""
proofs on correctness of the commitment & cipher to the message
"""
def prove_sign(params, pub, ciphertext, cm, k, r, m):
	""" prove correct encryption enc & commitment """
	(G, o, g1, h1, g2, e) = params
	(a, b) = ciphertext

	# create the witnesses
	wk = o.random()
	wm = o.random()
	wr = o.random()

	# compute h
	h = G.hashG1(cm.export())

	# compute the witnesses commitments
	Aw = wk * g1
	Bw = wk * pub + wm * h
	Cw = wm * g1 + wr * h1 

	# create the challenge
	c = to_challenge([g1, h1, g2, a, b, cm, h, Aw, Bw, Cw])

	# create responses
	rk = (wk - c * k) % o
	rm = (wm - c * m) % o
	rr = (wr - c * r) % o

	# return the proof
	return (c, rk, rm, rr)

def verify_sign(params, pub, ciphertext, cm, proof):
	""" verify correct encryption enc & commitment """
	(G, o, g1, h1, g2, e) = params
	(a, b) = ciphertext
	(c, rk, rm, rr) = proof

	# re-compute h
	h = G.hashG1(cm.export())

	# re-compute witnesses commitments
	Aw = c * a + rk * g1
	Bw = c * b + rk * pub + rm * h
	Cw = c * cm + rm * g1 + rr * h1

	# compute the challenge prime
	return c == to_challenge([g1, h1, g2, a, b, cm, h, Aw, Bw, Cw])


"""
proofs on correctness of the aggregated value (X + m*Y)
"""
def prove_show(params, vk, m):
	""" prove correct of kappa=(X + m*Y) """
	(G, o, g1, h1, g2, e) = params
	(g2, X, Y) = vk

	# create the witnesses
	wm = o.random()

	# compute the witnesses commitments
	Aw = X + wm*Y

	# create the challenge
	c = to_challenge([g1, h1, g2, X, Y, Aw])

	# create responses 
	rm = (wm - c * m) % o

	# return the proof
	return (c, rm)

def verify_show(params, vk, kappa, proof):
	""" verify correct of kappa=(X + m*Y) """
	(G, o, g1, h1, g2, e) = params
	(g2, X, Y) = vk
	(c, rm) = proof

	# re-compute witnesses commitments
	Aw = c*kappa + rm*Y + (1-c)*X

	# compute the challenge prime
	return c == to_challenge([g1, h1, g2, X, Y, Aw])

