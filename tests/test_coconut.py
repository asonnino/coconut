from coconut.scheme import *


def test_threshold_authorities():
	q = 7 # number of messages
	private_m = [10] * 2 # private message
	public_m = [3] * 1 # public messages
	t, n = 2, 3 # number of authorities
	params = setup(q)
	(d, gamma) = elgamal_keygen(params) # El-Gamal keypair
	
	# generate commitment and encryption
	(cm, c, pi_s) = prepare_blind_sign(params, gamma, private_m, public_m=public_m)

	# generate key
	(sk, vk) = ttp_keygen(params, t, n)

	# aggregate verification keys
	aggr_vk = aggregate_vk(params, vk)

	# bind sign
	sigs_tilde = [blind_sign(params, ski, cm, c, gamma, pi_s, public_m=public_m) for ski in sk]

	# unblind
	sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]

	# aggregate credentials
	sigma = aggregate_sigma(params, sigs)

	# randomize credentials
	sigma = randomize(params, sigma)

	# generate kappa and proof of correctness
	(kappa, nu, pi_v) = show_blind_sign(params, aggr_vk, sigma, private_m)

	# verify signature
	assert blind_verify(params, aggr_vk, sigma, kappa, nu, pi_v, public_m=public_m)


def test_multi_authorities():
	q = 7 # number of messages
	private_m = [10] * 2 # hidden message
	public_m = [3] * 1 # clear messages
	n = 3 # number of authorities
	params = setup(q)
	(d, gamma) = elgamal_keygen(params) # El-Gamal keypair
	
	# generate commitment and encryption
	(cm, c, pi_s) = prepare_blind_sign(params, gamma, private_m, public_m=public_m)

	# generate key
	(sk, vk) = ttp_keygen(params, n, n)

	# aggregate verification keys
	aggr_vk = aggregate_vk(params, vk, threshold=False)

	# bind sign
	sigs_tilde = [blind_sign(params, ski, cm, c, gamma, pi_s, public_m=public_m) for ski in sk]

	# unblind
	sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]

	# aggregate credentials
	sigma = aggregate_sigma(params, sigs, threshold=False)

	# randomize credentials
	sigma = randomize(params, sigma)

	# generate kappa and proof of correctness
	(kappa, nu, pi_v) = show_blind_sign(params, aggr_vk, sigma, private_m)

	# verify signature
	assert blind_verify(params, aggr_vk, sigma, kappa, nu, pi_v, public_m=public_m)


	