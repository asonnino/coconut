from bplib.bp import BpGroup
from hashlib  import sha256
from binascii import hexlify, unhexlify
from petlib.bn import Bn


# ==================================================
# setup
# ==================================================
def setup():
	G = BpGroup()
	g1, g2 = G.gen1(), G.gen2()
	h1 = G.gen1()
	e, o = G.pair, G.order()
	return (G, o, g1, h1, g2, e)


# ==================================================
# aggregated signature
# ==================================================
def keygen_sign(params):
	""" generate a key pair for signature """
	(G, o, g1, h1, g2, e) = params
	(x, y) = o.random(), o.random()
	sk = (x, y)
	pk = (g2, x*g2, y*g2)
	return (sk, pk)

def sign(params, sk, m):
	""" sign a message """
	(G, o, g1, h1, g2, e) = params
	(x, y) = sk
	sig = (x+y*m) * h1
	return (h1, sig)

def aggregate(sig1, sig2):
	""" aggregate sgnatures """
	sig11 , sig12 = sig1
	sig21 , sig22 = sig2
	assert sig11 == sig21
	return (sig11, sig12+sig22)

def randomize_sign(params, sig):
	""" randomize signature """
	(G, o, g1, h1, g2, e) = params
	sig1 , sig2 = sig
	t = o.random()
	return ( t*sig1 , t*sig2 )

def private_sign(params, sk, cm, c, pk_enc, proof):
	(G, o, g1, h1, g2, e) = params
	(x, y) = sk
	(a, b) = c

	assert verify_sign(params, pk_enc, c, cm, proof)

	h = G.hashG1(cm.export())
	c_prime = (x*h + y*b)
	return (h, c_prime)

def verify(params, pk, m, sig):
	""" verify a signature """
	(G, o, g1, h1, g2, e) = params
	(g, X, Y) = pk
	sig1 , sig2 = sig
	return not sig1.isinf() and e(sig1, X + m * Y) == e(sig2, g)

	
# ==================================================
# homomorphic encryptions
# ==================================================
def enc_side(params, pk, counter, h):
    """ encrypts the values of a small counter """
    assert -2**8 < counter < 2**8
    (G, o, g1, h1, g2, e) = params
    k = o.random()
    a = k * h
    b = k * pk + counter * h
    return (a, b, k)


# ==================================================
# zero-knowledge proofs
# ==================================================
def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)

def prove_sign(params, pk, ciphertext, cm, k, r, m):
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
	Aw = wk * h
	Bw = wk * pk + wm * h
	Cw = wm * g1 + wr * h1 

	# create the challenge
	c = to_challenge([g1, h1, g2, a, b, cm, h, Aw, Bw, Cw])

	# create responses for k and m
	rk = (wk - c * k) % o
	rm = (wm - c * m) % o
	rr = (wr - c * r) % o

	# return the proof
	return (c, (rk, rm, rr))

def verify_sign(params, pk, ciphertext, cm, proof):
	""" verify correct encryption enc & commitment """
	(G, o, g1, h1, g2, e) = params
	a, b = ciphertext
	(c, (rk, rm, rr)) = proof

	# re-compute h
	h = G.hashG1(cm.export())

	# re-compute witnesses commitments
	Aw = c * a + rk * h
	Bw = c * b + rk * pk + rm * h
	Cw = c * cm + rm * g1 + rr * h1

	# compute the challenge prime
	c_prime = to_challenge([g1, h1, g2, a, b, cm, h, Aw, Bw, Cw])

	# return whether the proof succeeded
	return c_prime == c



