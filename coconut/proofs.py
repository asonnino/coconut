""" Coconut zero-knowledge proofs. """
from petlib.bn import Bn
from bplib.bp import BpGroup
from hashlib import sha256
from binascii import hexlify
from coconut.utils import ec_sum


def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    return Bn.from_binary(Chash)


def make_pi_s(params, gamma, ciphertext, cm, k, r, public_m, private_m):
	""" prove correctness of ciphertext and cm """
	(G, o, g1, hs, g2, e) = params
	attributes = private_m + public_m
	assert len(ciphertext) == len(k) and len(ciphertext) == len(private_m)
	assert len(attributes) <= len(hs)
	# create the witnesses
	wr = o.random()
	wk = [o.random() for _ in k]
	wm = [o.random() for _ in attributes]
	# compute h
	h = G.hashG1(cm.export())
	# compute the witnesses commitments
	Aw = [wki*g1 for wki in wk]
	Bw = [wk[i]*gamma + wm[i]*h for i in range(len(private_m))]
	Cw = wr*g1 + ec_sum([wm[i]*hs[i] for i in range(len(attributes))])
	# create the challenge
	c = to_challenge([g1, g2, cm, h, Cw]+hs+Aw+Bw)
	# create responses
	rr = (wr - c * r) % o
	rk = [(wk[i] - c*k[i]) % o for i in range(len(wk))]
	rm = [(wm[i] - c*attributes[i]) % o for i in range(len(wm))]
	return (c, rk, rm, rr)


def verify_pi_s(params, gamma, ciphertext, cm, proof):
	""" verify orrectness of ciphertext and cm """
	(G, o, g1, hs, g2, e) = params
	(a, b) = zip(*ciphertext)
	(c, rk, rm, rr) = proof
	assert len(ciphertext) == len(rk)
	# re-compute h
	h = G.hashG1(cm.export())
	# re-compute witnesses commitments
	Aw = [c*a[i] + rk[i]*g1 for i in range(len(rk))]
	Bw = [c*b[i] + rk[i]*gamma + rm[i]*h for i in range(len(ciphertext))]
	Cw = c*cm + rr*g1 + ec_sum([rm[i]*hs[i] for i in range(len(rm))])
	# compute the challenge prime
	return c == to_challenge([g1, g2, cm, h, Cw]+hs+Aw+Bw)


def make_pi_v(params, aggr_vk, sigma, private_m, t):
	""" prove correctness of kappa and nu """
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	# create the witnesses
	wm = [o.random() for _ in private_m]
	wt = o.random()
	# compute the witnesses commitments
	Aw = wt*g2 + alpha + ec_sum([wm[i]*beta[i] for i in range(len(private_m))])
	Bw = wt*h
	# create the challenge
	c = to_challenge([g1, g2, alpha, Aw, Bw]+hs+beta)
	# create responses 
	rm = [(wm[i] - c*private_m[i]) % o for i in range(len(private_m))]
	rt = (wt - c*t) % o
	return (c, rm, rt)

def verify_pi_v(params, aggr_vk, sigma, kappa, nu, pi_v):
	""" verify correctness of kappa and nu """
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	(c, rm, rt) = pi_v
	# re-compute witnesses commitments
	Aw = c*kappa + rt*g2 + (1-c)*alpha + ec_sum([rm[i]*beta[i] for i in range(len(rm))])
	Bw = c*nu + rt*h
	# compute the challenge prime
	return c == to_challenge([g1, g2, alpha, Aw, Bw]+hs+beta)




