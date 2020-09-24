from coconut.scheme_up import setup, prepare_blind_sign, keygen, agg_key, blind_sign, agg_cred
from coconut.scheme import prove_cred, verify_cred

def test_multi_authority():
    q = 7 # number of attributes
    private_m = [10] * 2 # private attributes
    public_m = [3] * 1 # public attributes
    n = 3 # number of authorities
    params = setup(q)

    # generate commitment and encryption
    Ls, Lambda = prepare_blind_sign(params, private_m, public_m=public_m)

    # generate key
    keys = [keygen(params) for _ in range(n)]
    (sk, vk) = zip(*keys)

    # aggregate verification keys
    aggr_vk = agg_key(params, vk, threshold=False)

    # bind sign
    sigs_tilde = [blind_sign(params, ski, Lambda, public_m=public_m) for ski in sk]

    # aggregate credentials
    sigma = agg_cred(params, aggr_vk, sigs_tilde, Ls, threshold=False)

    # Remove extras
    (G, o, g1, hs, h_blind, g2, e) = params
    (g2, alpha, beta, _) = aggr_vk

    min_params = (G, o, g1, hs, g2, e)
    min_aggr_vk = (g2, alpha, beta)

    # randomize credentials and generate any cryptographic material to verify them
    Theta = prove_cred(min_params, min_aggr_vk, sigma, private_m)

    # verify credentials
    verify_cred(min_params, min_aggr_vk, Theta, public_m=public_m)
