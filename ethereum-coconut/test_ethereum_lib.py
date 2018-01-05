""" tests """
from ethereum_lib import setup
from ethereum_lib import elgamal_keygen, elgamal_enc, elgamal_dec
from ethereum_lib import keygen, sign, aggregate_sign, aggregate_keys, randomize, verify
from ethereum_lib import prepare_blind_sign, blind_sign, elgamal_dec, show_blind_sign, blind_verify
from ethereum_lib import ttp_th_keygen, aggregate_th_sign
from ethereum_lib import mix_keygen, prepare_mix_sign, mix_sign, mix_aggregate_keys, show_mix_sign, mix_verify
from ethereum_lib import mix_ttp_th_keygen

from bn128 import FQ, pairing


# ==================================================
# test --  el gamal
# ==================================================
def test_elgamal():
	params = setup()
	(G, o, g1, hs, g2, e) = params
	m, h = 10, hs[0]
	(priv, pub) = elgamal_keygen(params)
	(a, b, k) = elgamal_enc(params, pub, m, h)
	c = (a, b)
	assert elgamal_dec(params, priv, c) == m*h


# ==================================================
# test --  sign
# ==================================================
def test_sign():
	params = setup()

	# user parameters
	m = 10

	# signer 1
	(sk1, vk1) = keygen(params)
	sig1 = sign(params, sk1, m)

	# signer 2
	(sk2, vk2) = keygen(params)
	sig2 = sign(params, sk2, m)

	# affregate signatures
	sig = aggregate_sign(sig1, sig2)

	# randomize signature
	sig = randomize(params, sig)

	# aggregate keys
	vk = aggregate_keys(vk1, vk2)

	# verify signature
	assert verify(params, vk, m, sig)


# ==================================================
# test -- blind sign
# ==================================================
def test_blind_sign():
	params = setup()

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
	(kappa, proof_v) = show_blind_sign(params, vk, m)

	# verify signature
	assert blind_verify(params, vk, kappa, sig, proof_v)


# ==================================================
# test --  threshold sign
# ==================================================
from random import shuffle
def test_threshold_sign():
	params = setup()

	# user parameters
	m = 10
	t, n = 2, 4

	# generate key
	(sk, vk, vvk) = ttp_th_keygen(params, t, n)

	# sign
	sigs = [sign(params, ski, m) for ski in sk]

	# affregate signatures
	sig = aggregate_th_sign(params, sigs)

	# randomize signature
	sig = randomize(params, sig)

	# verify signature
	assert verify(params, vvk, m, sig)


# ==================================================
# test -- mix sign
# ==================================================
def test_mix_sign():
	# user parameters
	q = 7 # number of messages
	hidden_m = [10] * 5 # hideen message
	clear_m = [3] * 2 # clear messages
	params = setup(q)
	(priv, pub) = elgamal_keygen(params) # El Gamal keypair
	
	# generate commitment and encryption for mix signature
	(cm, c, proof_s) = prepare_mix_sign(params, clear_m, hidden_m, pub)

	# signer 1
	(sk1, vk1) = mix_keygen(params, q)
	mix_sig1 = mix_sign(params, sk1, cm, c, pub, proof_s, clear_m)
	(h, enc_sig1) = mix_sig1
	sig1 = (h, elgamal_dec(params, priv, enc_sig1))

	# signer 1
	(sk2, vk2) = mix_keygen(params, q)
	mix_sig2 = mix_sign(params, sk2, cm, c, pub, proof_s, clear_m)
	(h, enc_sig2) = mix_sig2
	sig2 = (h, elgamal_dec(params, priv, enc_sig2))
	
	# aggregate signatures
	sig = aggregate_sign(sig1, sig2)

	# randomize signature
	sig = randomize(params, sig)

	# aggregate keys
	vk = mix_aggregate_keys([vk1, vk2])
	
	# generate kappa and proof of correctness
	(kappa, proof_v) = show_mix_sign(params, vk, hidden_m)

	# verify signature
	assert mix_verify(params, vk, kappa, sig, proof_v, clear_m)


# ==================================================
# test --  threshold mix sign
# ==================================================
def test_threshold_mix_sign():
	q = 7 # number of messages
	hidden_m = [10] * 2 # hideen message
	clear_m = [3] * 1 # clear messages
	t, n = 2, 3
	params = setup(q)
	(priv, pub) = elgamal_keygen(params) # El Gamal keypair
	
	# generate commitment and encryption for mix signature
	(cm, c, proof_s) = prepare_mix_sign(params, clear_m, hidden_m, pub)

	# generate key
	(sk, vk, vvk) = mix_ttp_th_keygen(params, t, n, q)

	# sign
	enc_sigs = [mix_sign(params, ski, cm, c, pub, proof_s, clear_m) for ski in sk]
	(h, enc_epsilon) = zip(*enc_sigs)
	sigs = [(h[0], elgamal_dec(params, priv, enc)) for enc in enc_epsilon]

	# aggregate signatures
	sig = aggregate_th_sign(params, sigs)

	# randomize signature
	sig = randomize(params, sig)

	# generate kappa and proof of correctness
	(kappa, proof_v) = show_mix_sign(params, vvk, hidden_m)

	# verify signature
	assert mix_verify(params, vvk, kappa, sig, proof_v, clear_m)


