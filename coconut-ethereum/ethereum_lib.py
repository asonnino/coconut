from wrapper import BpGroup, G1Elem, G2Elem
from hashlib  import sha256
from binascii import hexlify, unhexlify
#from petlib.bn import Bn # only used to hash challange
import numpy as np

from bn128 import FQ


# ==================================================
# setup
# ==================================================
def setup(q=1):
	""" generate all public parameters """
	assert q > 0
	G = BpGroup()
	g1, g2 = G.gen1(), G.gen2()
	hs = [G.hashG1(("h%s" % i).encode("utf8")) for i in range(q)]
	e, o = G.pair, G.order()
	return (G, o, g1, hs, g2, e)


# ==================================================
# El Gamal encryption scheme
# ==================================================
def elgamal_keygen(params):
   """ generate an El Gamal key pair """
   (G, o, g1, hs, g2, e) = params
   priv = o.random()
   pub = priv * g1
   return (priv, pub)

def elgamal_enc(params, pub, m, h):
    """ encrypts the values of a message h^m """
    (G, o, g1, hs, g2, e) = params
    k = o.random()
    a = k * g1
    b = k * pub + m * h
    return (a, b, k)

def elgamal_dec(params, priv, c):
    """ decrypts the message h^m """
    (G, o, g1, hs, g2, e) = params
    (a, b) = c
    return b - priv * a


# ==================================================
# aggregated signature
# ==================================================
"""
signature on clear message
"""
def keygen(params):
	""" generate a key pair for signature """
	(G, o, g1, hs, g2, e) = params
	(x, y) = o.random(), o.random()
	sk = (x, y)
	vk = (g2, x*g2, y*g2)
	return (sk, vk)

def sign(params, sk, m):
	""" sign a clear message """
	(G, o, g1, hs, g2, e) = params
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
	(G, o, g1, hs, g2, e) = params
	sig1 , sig2 = sig
	t = o.random()
	return ( t*sig1 , t*sig2 )

def verify(params, vk, m, sig):
	""" verify a signature on a clear message """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	sig1 , sig2 = sig
	return not sig1.isinf() and e(sig1, X + m * Y) == e(sig2, g2)

"""
signature on hidden message
"""
def prepare_blind_sign(params, m, pub):
	""" build elements for blind sign """
	(G, o, g1, hs, g2, e) = params
	# build commitment
	r = o.random()
	cm = m*g1 + r*hs[0] 
	# build El Gamal encryption
	h = G.hashG1(cm.export()) 
	(a, b, k) = elgamal_enc(params, pub, m, h)
	c = (a, b)
	# proof of correctness
	proof = prove_sign(params, pub, c, cm, k, r, m)
	return (cm, c, proof)

def blind_sign(params, sk, cm, c, pub, proof):
	""" blindly sign a message """
	(G, o, g1, hs, g2, e) = params
	(x, y) = sk
	(a, b) = c
	# verify proof of correctness
	if not verify_sign(params, pub, c, cm, proof):
		raise Exception('Parameters format error.')
	# issue signature
	h = G.hashG1(cm.export())
	enc_sig = (y*a, x*h + y*b)
	return (h, enc_sig)

def show_blind_sign(params, vk, m):
	""" build elements for blind verify """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	kappa = X + m*Y
	proof = prove_show(params, vk, m)
	return (kappa, proof)

def blind_verify(params, vk, kappa, sig, proof):
	""" verify a signature on a hidden message """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	sig1 , sig2 = sig
	return not sig1.isinf() \
		and verify_show(params, vk, kappa, proof) \
		and e(sig1, kappa) == e(sig2, g2)
	
"""
threshold signature
"""
def ttp_th_keygen(params, t, n):
	""" generate keys for threshold signature """
	(G, o, g1, hs, g2, e) = params
	# generate polynomials
	v = np.poly1d([o.random() for _ in range(0,t)])
	w = np.poly1d([o.random() for _ in range(0,t)])
	# generate shares
	x = [v(i) % o for i in range(1,n+1)]
	y = [w(i) % o for i in range(1,n+1)]
	# set keys
	sk = list(zip(x, y))
	vk = [(g2, xi*g2, yi*g2) for (xi, yi) in zip(x, y)]
	vvk = (g2, v(0)*g2, w(0)*g2)
	return (sk, vk, vvk)

def aggregate_th_sign(params, sigs):
	""" aggregate threshold signatures """
	(G, o, g1, hs, g2, e) = params
	t = len(sigs)
	# evaluate all lagrange basis polynomial li(0)
	l = [lagrange_basis(t, o, i, 0) for i in range(1,t+1)]
	# aggregate sigature
	h, epsilon = zip(*sigs)
	aggr_epsilon = ec_sum([l[i]*epsilon[i] for i in range(t)])
	return (h[0], aggr_epsilon)


"""
mixed hidden and clear messages
"""
def mix_keygen(params, q):
	""" generate a key pair for signature on at most q messages """
	(G, o, g1, hs, g2, e) = params
	x = o.random()
	y = [o.random() for _ in range(q)]
	sk = (x, y)
	vk = (g2, x*g2, [yi*g2 for yi in y])
	return (sk, vk)

def mix_ttp_th_keygen(params, t, n, q):
	""" generate keys for threshold signature """
	(G, o, g1, hs, g2, e) = params
	# generate polynomials
	v = np.poly1d([o.random() for _ in range(0,t)])
	w = [np.poly1d([o.random() for _ in range(0,t)]) for __ in range(q)]
	# generate shares
	x = [v(i) % o for i in range(1,n+1)]
	y = [[w[j](i) % o for j in range(len(w))] for i in range(1,n+1)]
	# set keys
	sk = list(zip(x, y))
	vk = [(g2, x[i]*g2, [y[i][j]*g2 for j in range(len(y[i]))]) for i in range(len(sk))]
	vvk = (g2, v(0)*g2, [wi(0)*g2 for wi in w])
	return (sk, vk, vvk)

def mix_aggregate_keys(keys):
	""" aggregate signers verification keys """
	assert len(keys) > 1
	g2 = keys[0][0]
	(_, X, Y) = zip(*keys)
	alpha = ec_sum(X)
	beta = [ec_sum(y) for y in list(zip(*Y))]
	return (g2, alpha, beta)

def prepare_mix_sign(params, clear_m, hidden_m, pub):
	""" build elements for blind sign """
	(G, o, g1, hs, g2, e) = params
	attributes = hidden_m + clear_m
	assert len(attributes) <= len(hs)
	# build commitment
	r = o.random()
	cm = r*g1 + ec_sum([attributes[i]*hs[i] for i in range(len(attributes))])
	# build El Gamal encryption
	h = G.hashG1(cm.export()) 
	enc = [elgamal_enc(params, pub, m, h) for m in hidden_m]
	(a, b, k) = zip(*enc)
	c = list(zip(a, b))
	# build proofs
	proof = prove_mix_sign(params, pub, c, cm, k, r, clear_m, hidden_m)
	return (cm, c, proof)

def mix_sign(params, sk, cm, c, pub, proof, m):
	""" blindly sign messages in c, and sign messages in m """
	(G, o, g1, hs, g2, e) = params
	(x, y) = sk
	(a, b) = zip(*c) 
	assert (len(c)+len(m)) <= len(hs)
	# verify proof of correctness
	assert verify_mix_sign(params, pub, c, cm, proof)
	# issue signature
	h = G.hashG1(cm.export())
	t1 = [mi*h for mi in m]
	t2 = ec_sum([yi*ai for yi,ai in zip(y,a)])
	t3 = x*h + ec_sum([yi*bi for yi,bi in zip(y,list(b)+t1)])
	return (h, (t2, t3))

def show_mix_sign(params, vk, m):
	""" build elements for mix verify """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	assert len(m) <= len(Y)
	kappa = X + ec_sum([m[i]*Y[i] for i in range(len(m))])
	proof = prove_mix_show(params, vk, m)
	return (kappa, proof)

def mix_verify(params, vk, kappa, sig, proof, m):
	""" verify a signature on a mixed clear and hidden message """
	(G, o, g1, h1, g2, e) = params
	(g2, X, Y) = vk
	(h, epsilon) = sig
	hidden_m_len = len(proof[1])
	assert len(m)+hidden_m_len <= len(Y)
	# verify proof of correctness
	assert verify_mix_show(params, vk, kappa, proof)
	print(verify_mix_show(params, vk, kappa, proof))
	# add clear text messages
	aggr = G2Elem.inf ### EDITED ### 
	if len(m) != 0:
		aggr = ec_sum([m[i]*Y[i+hidden_m_len] for i in range(len(m))])
	# verify
	return not h.isinf() and e(h, kappa+aggr) == e(epsilon, g2)



# ==================================================
# utils and zero-knowledge proofs
# ==================================================
"""
utilities
"""
def lagrange_basis(t, o, i, x=0):
	""" generates the lagrange basis polynomial li(x), for a polynomial of degree t-1 """
	numerator, denominator = 1, 1
	for j in range(1,t+1):
		if j != i:
			numerator = (numerator * (x - j)) % o
			denominator = (denominator * (i - j)) % o
	return (numerator * inv(denominator, o)) % o ### EDITED ###

def ec_sum(list):
	""" sum EC points list """
	ret = list[0]
	for i in range(1,len(list)):
		ret = ret + list[i]
	return ret

def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    #return Bn.from_binary(Chash)
    return int.from_bytes(Chash, 'big') ### EDITED ###

def is_same_length(*args):
	""" check if arguments are of the same length """
	assert len(args) > 1
	for i in range(1,len(args)):
		if len(args[i-1]) != len(args[i]): return False
	return True

def inv(a, n):  ### EDITED ###
	""" extended euclidean algorithm """
	if a == 0:
		return 0
	lm, hm = 1, 0
	low, high = a % n, n
	while low > 1:
		r = high//low
		nm, new = hm-lm*r, high-low*r
		lm, low, hm, high = nm, new, lm, low
	return lm % n

"""
proofs on correctness of the commitment & cipher to the message
"""
def prove_sign(params, pub, ciphertext, cm, k, r, m):
	""" prove correct encryption enc & commitment """
	(G, o, g1, hs, g2, e) = params
	(a, b) = ciphertext
	# create the witnesses
	wk, wm, wr = o.random(), o.random(), o.random()
	# compute h
	h = G.hashG1(cm.export())
	# compute the witnesses commitments
	Aw = wk * g1
	Bw = wk * pub + wm * h
	Cw = wm * g1 + wr * hs[0] 
	# create the challenge
	c = to_challenge([g1, g2, a, b, cm, h, Aw, Bw, Cw] + hs)
	# create responses
	rk = (wk - c * k) % o
	rm = (wm - c * m) % o
	rr = (wr - c * r) % o
	return (c, rk, rm, rr)

def verify_sign(params, pub, ciphertext, cm, proof):
	""" verify correct encryption enc & commitment """
	(G, o, g1, hs, g2, e) = params
	(a, b) = ciphertext
	(c, rk, rm, rr) = proof
	# re-compute h
	h = G.hashG1(cm.export())
	# re-compute witnesses commitments
	Aw = c * a + rk * g1
	Bw = c * b + rk * pub + rm * h
	Cw = c * cm + rm * g1 + rr * hs[0]
	# compute the challenge prime
	return c == to_challenge([g1, g2, a, b, cm, h, Aw, Bw, Cw] + hs)


"""
proofs on correctness of the aggregated value (X + m*Y)
"""
def prove_show(params, vk, m):
	""" prove correct of kappa=(X + m*Y) """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	# create the witnesses
	wm = o.random()
	# compute the witnesses commitments
	Aw = X + wm*Y
	# create the challenge
	c = to_challenge([g1, g2, X, Y, Aw] + hs)
	# create responses 
	rm = (wm - c * m) % o
	return (c, rm)

def verify_show(params, vk, kappa, proof):
	""" verify correct of kappa=(X + m*Y) """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	(c, rm) = proof
	# re-compute witnesses commitments
	Aw = c*kappa + rm*Y + X - c*X  ### EDITED ###
	# compute the challenge prime
	return c == to_challenge([g1, g2, X, Y, Aw] + hs)


"""
proofs on correctness of the commitment & cipher on multiple messages
"""
def prove_mix_sign(params, pub, ciphertext, cm, k, r, clear_m, hidden_m):
	""" prove correct encryption enc & commitment """
	(G, o, g1, hs, g2, e) = params
	attributes = hidden_m + clear_m
	assert is_same_length(ciphertext, k, hidden_m)
	assert len(attributes) <= len(hs)
	# create the witnesses
	wr = o.random()
	wk = [o.random() for _ in k]
	wm = [o.random() for _ in attributes]
	# compute h
	h = G.hashG1(cm.export())
	# compute the witnesses commitments
	Aw = [wki*g1 for wki in wk]
	Bw = [wk[i]*pub + wm[i]*h for i in range(len(hidden_m))]
	Cw = wr*g1 + ec_sum([wm[i]*hs[i] for i in range(len(attributes))])
	# create the challenge
	c = to_challenge([g1, g2, cm, h, Cw]+hs+Aw+Bw)
	# create responses
	rr = (wr - c * r) % o
	rk = [(wk[i] - c * k[i]) % o for i in range(len(wk))]
	rm = [(wm[i] - c * attributes[i]) % o for i in range(len(wm))]
	return (c, rk, rm, rr)

def verify_mix_sign(params, pub, ciphertext, cm, proof):
	""" verify correct encryption enc & commitment """
	(G, o, g1, hs, g2, e) = params
	(a, b) = zip(*ciphertext)
	(c, rk, rm, rr) = proof
	assert is_same_length(ciphertext, rk)
	# re-compute h
	h = G.hashG1(cm.export())
	# re-compute witnesses commitments
	Aw = [c*a[i] + rk[i]*g1 for i in range(len(rk))]
	Bw = [c*b[i] + rk[i]*pub + rm[i]*h for i in range(len(ciphertext))]
	Cw = c*cm + rr*g1 + ec_sum([rm[i]*hs[i] for i in range(len(rm))])
	# compute the challenge prime
	return c == to_challenge([g1, g2, cm, h, Cw]+hs+Aw+Bw)



"""
proofs on correctness of the aggregated value (X + m*Y) on multiple messages
"""
def prove_mix_show(params, vk, m):
	""" prove correct of kappa=(X + m*Y) """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	# create the witnesses
	wm = [o.random() for _ in m]
	# compute the witnesses commitments
	Aw = X + ec_sum([wm[i]*Y[i] for i in range(len(m))])
	# create the challenge
	c = to_challenge([g1, g2, X, Aw]+hs+Y)
	# create responses 
	rm = [(wm[i] - c * m[i]) % o for i in range(len(m))]
	return (c, rm)

def verify_mix_show(params, vk, kappa, proof):
	""" verify correct of kappa=(X + m*Y) """
	(G, o, g1, hs, g2, e) = params
	(g2, X, Y) = vk
	(c, rm) = proof
	# re-compute witnesses commitments
	Aw = c*kappa + X - c*X + ec_sum([rm[i]*Y[i] for i in range(len(rm))]) ### EDITED ###
	# compute the challenge prime
	return c == to_challenge([g1, g2, X, Aw]+hs+Y)
