"""Performance measurements for authenticated bank contract."""
import time
import numpy
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples import tumbler
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

# crypto parameters
t, n = 2, 3 # threshold and total numbero of authorities
bp_params = bp_setup() # bp system's parameters
(sk, vk, vvk) = ttp_th_keygen(bp_params, t, n) # signers keys
packed_vvk = (pack(vvk[0]),pack(vvk[1]),pack(vvk[2]))

# tumbler parameter
ID = 10 # random ID
merchant_addr = 'merchant_addr' # merchant address


# some crypto
# ------------------------------------
instance = {
    'type' : 'TList',
    'list' : [],
    'vvk' : packed_vvk
}

hasher = sha256()
hasher.update(dumps(instance).encode('utf8'))
m = Bn.from_binary(hasher.digest())
auth_sigs = [sign(bp_params, ski, m) for ski in sk]
auth_sig = aggregate_th_sign(bp_params, auth_sigs)
# ------------------------------------

##
RUNS = 10000


def main():
    tumbler.contract._populate_empty_checkers()
    print "operation\t\tmean (ms)\t\tsd (ms)\t\truns"

    # == init ===============
    init_tx = tumbler.init()

    # == create_tumbler ===============
    # gen
    times = []
    for i in range(RUNS):
        start_time = time.time()
        tumbler.create_tumbler(
            (init_tx['transaction']['outputs'][0],),
            None,
            None,
            vvk,
            auth_sig
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] create_tumbler tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    create_tumbler_tx = tumbler.create_tumbler(
        (init_tx['transaction']['outputs'][0],),
        None,
        None,
        vvk,
        auth_sig
    )
    solution = transaction_to_solution(create_tumbler_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        tumbler.contract.checkers['create_tumbler'](
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
    print "[c] create_tumbler tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)


    # == redeem ===============
    # gen

    # some crypto
    # ------------------------------------
    hasher = sha256()
    hasher.update(dumps(ID).encode('utf8'))
    hasher.update(dumps(merchant_addr).encode('utf8'))
    m = Bn.from_binary(hasher.digest())
    (priv, pub) = elgamal_keygen(bp_params)
    (cm, c, proof_s) = prepare_blind_sign(bp_params, m, pub)
    enc_sigs = [blind_sign(bp_params, ski, cm, c, pub, proof_s) for ski in sk]
    (h, enc_epsilon) = zip(*enc_sigs)
    sigs = [(h[0], elgamal_dec(bp_params, priv, enc)) for enc in enc_epsilon]
    sig = aggregate_th_sign(bp_params, sigs)
    sig = randomize(bp_params, sig)
    # reveal ID and merchant addr
    #print(verify(bp_params, vvk, m, sig))
    # ------------------------------------

    times = []
    for i in range(RUNS):
        start_time = time.time()
        tumbler.redeem(
            (create_tumbler_tx['transaction']['outputs'][1],),
            None,
            (dumps(ID),dumps(merchant_addr)),
            sig,
            vvk,
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] redeem tx\t\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    redeem_tx = tumbler.redeem(
        (create_tumbler_tx['transaction']['outputs'][1],),
        None,
        (dumps(ID),dumps(merchant_addr)),
        sig,
        vvk,
    )
    solution = transaction_to_solution(redeem_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        tumbler.contract.checkers['redeem'](
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
    print "[c] redeem tx\t\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    '''
    print("\nTransactions:")
    print(create_tumbler_tx)
    print(redeem_tx)
    '''


if __name__ == '__main__':
    main()
