""" Coconut threshold credentials scheme """
from bplib.bp import BpGroup, G2Elem
from coconut.utils import *
from coconut.proofs import *


def setup(q=1):
	""" generate all public parameters """
	assert q > 0
	G = BpGroup()
	(g1, g2) = G.gen1(), G.gen2()
	hs = [G.hashG1(("h%s" % i).encode("utf8")) for i in range(q)]
	(e, o) = G.pair, G.order()
	return (G, o, g1, hs, g2, e)


def ttp_keygen(params, t, n, q):
	""" generate keys for threshold signature (executed by a TTP) """
	assert n >= t and t > 0 and q > 0
	(G, o, g1, hs, g2, e) = params
	# generate polynomials
	v = [o.random() for _ in range(0,t)]
	w = [[o.random() for _ in range(0,t)] for __ in range(q)]
	# generate shares
	x = [poly_eval(v,i) % o for i in range(1,n+1)]
	y = [[poly_eval(wj,i) % o for wj in w] for i in range(1,n+1)]
	# set keys
	sk = list(zip(x, y))
	vk = [(g2, x[i]*g2, [y[i][j]*g2 for j in range(len(y[i]))]) for i in range(len(sk))]
	return (sk, vk)


def aggregate_vk(params, vk, threshold=True):
	""" aggregate the verification keys """
	(G, o, g1, hs, g2, e) = params
	(_, alpha, beta) = zip(*vk)
	t = len(vk)
	q = len(beta[0])
	# evaluate all lagrange basis polynomial li(0)
	l = [lagrange_basis(t, o, i, 0) for i in range(1,t+1)] if threshold else [1 for _ in range(t)]
	# aggregate keys
	aggr_alpha = ec_sum([l[i]*alpha[i] for i in range(t)])
	aggr_beta = [ec_sum([l[i]*beta[i][j] for i in range(t)]) for j in range(q)]
	return (g2, aggr_alpha, aggr_beta)


def prepare_blind_sign(params, gamma, private_m, public_m=[]):
	""" build cryptographic material for blind sign """
	assert len(private_m) > 0
	(G, o, g1, hs, g2, e) = params
	attributes = private_m + public_m
	assert len(attributes) <= len(hs)
	# build commitment
	r = o.random()
	cm = r*g1 + ec_sum([attributes[i]*hs[i] for i in range(len(attributes))])
	# build El Gamal encryption
	h = G.hashG1(cm.export()) 
	enc = [elgamal_enc(params, gamma, m, h) for m in private_m]
	(a, b, k) = zip(*enc)
	c = list(zip(a, b))
	# build proofs
	pi_s = make_pi_s(params, gamma, c, cm, k, r, public_m, private_m)
	return (cm, c, pi_s)


def blind_sign(params, sk, cm, c, gamma, pi_s, public_m=[]):
	""" blindly sign private attributes """
	(G, o, g1, hs, g2, e) = params
	(x, y) = sk
	(a, b) = zip(*c) 
	assert (len(c)+len(public_m)) <= len(hs)
	# verify proof of correctness
	assert verify_pi_s(params, gamma, c, cm, pi_s)
	# issue signature
	h = G.hashG1(cm.export())
	t1 = [mi*h for mi in public_m]
	t2 = ec_sum([yi*ai for yi,ai in zip(y,a)])
	t3 = x*h + ec_sum([yi*bi for yi,bi in zip(y,list(b)+t1)])
	sigma_tilde = (h, (t2, t3))
	return sigma_tilde


def unblind(params, sigma_tilde, d):
	""" unblind the credentials """
	(h, c_tilde) = sigma_tilde
	sigma = (h, elgamal_dec(params, d, c_tilde))
	return sigma


def aggregate_sigma(params, sigs, threshold=True):
	""" aggregate partial credentials """
	(G, o, g1, hs, g2, e) = params
	t = len(sigs)
	# evaluate all lagrange basis polynomial li(0)
	l = [lagrange_basis(t, o, i, 0) for i in range(1,t+1)] if threshold else [1 for _ in range(t)]
	# aggregate sigature
	(h, s) = zip(*sigs)
	aggr_s = ec_sum([l[i]*s[i] for i in range(t)])
	return (h[0], aggr_s)


def randomize(params, sig):
	""" randomize credentials (after aggregation) """
	(G, o, g1, hs, g2, e) = params
	(h , s) = sig
	r = o.random()
	return ( r*h , r*s )


def show_blind_sign(params, aggr_vk, sigma, private_m):
	""" build cryptographic material for blind verify """
	assert len(private_m) > 0
	(G, o, g1, hs, g2, e) = params
	(g2, alpha, beta) = aggr_vk
	(h, s) = sigma
	assert len(private_m) <= len(beta)
	t = o.random()
	kappa = t*g2 + alpha + ec_sum([private_m[i]*beta[i] for i in range(len(private_m))])
	nu = t*h
	pi_v = make_pi_v(params, aggr_vk, sigma, private_m, t)
	return (kappa, nu, pi_v)


def blind_verify(params, aggr_vk, sigma, kappa, nu, pi_v, public_m=[]):
	""" verify credentials """
	(G, o, g1, h1, g2, e) = params
	(g2, _, beta) = aggr_vk
	(h, s) = sigma
	private_m_len = len(pi_v[1])
	assert len(public_m)+private_m_len <= len(beta)
	# verify proof of correctness
	assert verify_pi_v(params, aggr_vk, sigma, kappa, nu, pi_v)
	# add clear text messages
	aggr = G2Elem.inf(G) 
	if len(public_m) != 0:
		aggr = ec_sum([public_m[i]*beta[i+private_m_len] for i in range(len(public_m))])
	# verify
	return not h.isinf() and e(h, kappa+aggr) == e(s+nu, g2)


