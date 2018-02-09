"""Performance measurements for authenticated bank contract."""
import time
import numpy
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples import petition
# petlib
from chainspacecontract.examples.utils import key_gen as pet_keygen
from chainspacecontract.examples.utils import setup as pet_setup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.coconut_util import pet_pack, pet_unpack, pack, unpackG1, unpackG2
from chainspacecontract.examples.coconut_lib import setup as bp_setup
from chainspacecontract.examples.coconut_lib import ttp_th_keygen, elgamal_keygen, elgamal_dec, sign, verify
from chainspacecontract.examples.coconut_lib import prepare_blind_sign, blind_sign, aggregate_th_sign, randomize
from chainspacecontract.examples.coconut_lib import verify, show_mix_sign, mix_verify, prepare_mix_sign, mix_sign
from chainspacecontract.examples.coconut_lib import show_coconut_petition, coconut_petition_verify

# crypto parameters
t, n = 4, 5 # threshold and total numbero of authorities
bp_params = bp_setup() # bp system's parameters
(sk, vk, vvk) = ttp_th_keygen(bp_params, t, n) # signers keys

# petition parameters
UUID = Bn(1234)
options = ['YES', 'NO']
pet_params = pet_setup()
(priv_owner, pub_owner) = pet_keygen(pet_params)


##
RUNS = 10000


def main():
    petition.contract._populate_empty_checkers()
    print "operation\t\tmean (ms)\t\tsd (ms)\t\truns"

    # == init ===============
    init_tx = petition.init()

    # == create_petition ===============
    # gen
    times = []
    for i in range(RUNS):
        start_time = time.time()
        petition.create_petition(
            (init_tx['transaction']['outputs'][0],),
            None,
            None,
            UUID,
            options,
            priv_owner,
            pub_owner,
            vvk
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] create_petition tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    create_petition_tx = petition.create_petition(
        (init_tx['transaction']['outputs'][0],),
        None,
        None,
        UUID,
        options,
        priv_owner,
        pub_owner,
        vvk
    )
    solution = transaction_to_solution(create_petition_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        petition.contract.checkers['create_petition'](
            solution['inputs'],
            solution['referenceInputs'],
            solution['parameters'],
            solution['outputs'],
            solution['returns'],
            solution['dependencies'],
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[c] create_petition tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)


    # == sign ===============
    # gen
    old_petition = create_petition_tx['transaction']['outputs'][1]
    old_list = create_petition_tx['transaction']['outputs'][2]

    # some crypto
    # ------------------------------------
    (priv_signer, pub_signer) = elgamal_keygen(bp_params)
    m = priv_signer
    (cm, c, proof_s) = prepare_blind_sign(bp_params, m, pub_signer)
    enc_sigs = [blind_sign(bp_params, ski, cm, c, pub_signer, proof_s) for ski in sk]
    (h, enc_epsilon) = zip(*enc_sigs)
    sigs = [(h[0], elgamal_dec(bp_params, priv_signer, enc)) for enc in enc_epsilon]
    sig = aggregate_th_sign(bp_params, sigs)
    sig = randomize(bp_params, sig)
    (kappa, nu, proof_v) = show_coconut_petition(bp_params, vvk, m, UUID)
    #print(coconut_petition_verify(bp_params, vvk, kappa, sig, proof_v, UUID, nu))
    # ------------------------------------

    times = []
    for i in range(RUNS):
        start_time = time.time()
        petition.sign(
            (old_petition, old_list),
            None,
            (dumps([1, 0]),),
            priv_signer,
            sig,
            vvk
            )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] sign tx\t\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    sign_tx = petition.sign(
        (old_petition, old_list),
        None,
        (dumps([1, 0]),),
        priv_signer,
        sig,
        vvk
    )
    solution = transaction_to_solution(sign_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        petition.contract.checkers['sign'](
            solution['inputs'],
            solution['referenceInputs'],
            solution['parameters'],
            solution['outputs'],
            solution['returns'],
            solution['dependencies'],
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[c] sign tx\t\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    '''
    print("\nTransactions:")
    print(create_petition_tx)
    print(sign_tx)
    '''


if __name__ == '__main__':
    main()
