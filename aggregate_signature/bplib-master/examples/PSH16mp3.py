""" A Skeleton implementation of the MP3 presence protocol:

MP3: A More Efficient Private Presence Protocol
Rahul Parhi, Michael Schliep, Nicholas Hopper
(Submitted on 10 Sep 2016)
https://arxiv.org/abs/1609.02987

"""

from bplib.bp import BpGroup

def params():
	G = BpGroup()
	Zp = G.order()
	return (G, Zp)

def managerkey(params):
	G, Zp = params()

	Ga = Zp.random() * G.gen1()
	Ha = Zp.random() * G.gen2()
	gamma_a = Zp.random()

	managerkey_a = (Ga, Ha, gamma_a)

	x_af = Zp.random()

	ex = (gamma_a.mod_add(x_af,Zp)).mod_inverse(Zp)

	A_af = x_af.mod_mul(ex,Zp) * Ga
	B_af = ex * Ha

	decryptionkey_a = (x_af, A_af, B_af)

	return managerkey_a, decryptionkey_a

def register(params, managerkey_a):
	G, Zp = params()
	(Ga, Ha, gamma_a) = managerkey_a

	kappa = Zp.random()

	Cj_a1 = kappa*(gamma_a * Ga)
	Cj_a2 = kappa*Ha

	Kj_a = G.pair(Ga, Ha) ** kappa

	record_a = (Cj_a1, Cj_a2)
	key_a = Kj_a
	return (record_a, key_a)	

def lookup(params, decryptionkey_a, record_a):
	G, Zp = params()

	(x_af, A_af, B_af) = decryptionkey_a
	(Cj_a1, Cj_a2) = record_a

	K = G.pair(Cj_a1, B_af).mul(G.pair(A_af, Cj_a2))
	return K

def test_all():

	G, Zp = params()

	# Derive friend key
	managerkey_a, decryptionkey_a = managerkey(params)

	# Registration
	record_a, key_a = register(params, managerkey_a)

	# Lookup
	K = lookup(params, decryptionkey_a, record_a)

	assert key_a.eq( K )