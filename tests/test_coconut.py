from coconut.scheme import *


def test_threshold_authorities():
	q = 7 # number of attributes
	private_m = [10] * 2 # private attributes
	public_m = [3] * 1 # public attributes
	t, n = 2, 3 # number of authorities
	params = setup(q)
	(d, gamma) = elgamal_keygen(params) # El-Gamal keypair
	
	# generate commitment and encryption
	Lambda = prepare_blind_sign(params, gamma, private_m, public_m=public_m)

	# generate key
	(sk, vk) = ttp_keygen(params, t, n)

	# aggregate verification keys
	aggr_vk = agg_key(params, vk)

	# bind sign
	sigs_tilde = [blind_sign(params, ski, gamma, Lambda, public_m=public_m) for ski in sk]

	# unblind
	sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]

	# aggregate credentials
	sigma = agg_cred(params, sigs)

	# randomize credentials and generate any cryptographic material to verify them
	Theta = prove_cred(params, aggr_vk, sigma, private_m)

	# verify credentials
	assert verify_cred(params, aggr_vk, Theta, public_m=public_m)


def test_multi_authorities():
    q = 7 # number of attributes
    private_m = [10] * 2 # private attributes
    public_m = [3] * 1 # public attributes
    n = 3 # number of authorities
    params = setup(q)
    (d, gamma) = elgamal_keygen(params) # El-Gamal keypair

    # generate commitment and encryption
    Lambda = prepare_blind_sign(params, gamma, private_m, public_m=public_m)

    # generate key
    (sk, vk) = ttp_keygen(params, n, n)

    # aggregate verification keys
    aggr_vk = agg_key(params, vk, threshold=False)

    # bind sign
    sigs_tilde = [blind_sign(params, ski, gamma, Lambda, public_m=public_m) for ski in sk]

    # unblind
    sigs = [unblind(params, sigma_tilde, d) for sigma_tilde in sigs_tilde]

    # aggregate credentials
    sigma = agg_cred(params, sigs, threshold=False)

    # randomize credentials and generate any cryptographic material to verify them
    Theta = prove_cred(params, aggr_vk, sigma, private_m)

    # verify credentials
    assert verify_cred(params, aggr_vk, Theta, public_m=public_m)


	
