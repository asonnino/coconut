"""Performance measurements for authenticated bank contract."""
import time
import numpy
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples import coconut
# petlib
from chainspacecontract.examples.utils import key_gen as pet_keygen
from chainspacecontract.examples.utils import setup as pet_setup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.coconut_util import pack, unpackG1, unpackG2
from chainspacecontract.examples.coconut_lib import setup, elgamal_keygen, mix_ttp_th_keygen
from chainspacecontract.examples.coconut_lib import elgamal_dec, aggregate_th_sign, randomize, sign, verify
from chainspacecontract.examples.coconut_lib import verify, show_mix_sign, mix_verify, prepare_mix_sign, mix_sign
from bplib.bp import BpGroup, G2Elem

# crypto parameters
q = 1 # max number of messages
t, n = 2, 2 # threshold and total numbero of authorities
callback = 'hello.init' # id of the callback contract
params = setup(q) # system's parameters
clear_m = [] # messages for plaintext signature
hidden_m = [1] # messages for blind signature
(priv, pub) = elgamal_keygen(params) # user's key pair 
(sk, vk, vvk) = mix_ttp_th_keygen(params, t, n, q) # signers keys

# some crypto
# ------------------------------------
packed_vvk = (pack(vvk[0]),pack(vvk[1]),[pack(vvk[2][i]) for i in range(q)])
instance = {
    'type' : 'CoCoInstance',
    'q' : q,
    't' : t,
    'n' : n,
    'callback' : callback,
    'verifier' : packed_vvk
}
hasher = sha256()
hasher.update(dumps(instance).encode('utf8'))
m = Bn.from_binary(hasher.digest())
sigs = [mix_sign(params, ski, None, [], [m]) for ski in sk]
auth_sig = aggregate_th_sign(params, sigs)
#print(mix_verify(params, vvk, None, sig, None, [m]))
# ------------------------------------


##
RUNS = 10000


def main():
    coconut.contract._populate_empty_checkers()
    print "operation\t\tmean (ms)\t\tsd (ms)\t\truns"

    # == init ===============
    init_tx = coconut.init()

    # == create ===============
    # gen
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.create(
            (init_tx['transaction']['outputs'][0],),
            None,
            None,
            q,
            t,
            n,
            callback, 
            vvk,
            auth_sig
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] create tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    create_tx = coconut.create(
        (init_tx['transaction']['outputs'][0],),
        None,
        None,
        q,
        t,
        n,
        callback, 
        vvk,
        auth_sig
    )
    solution = transaction_to_solution(create_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.contract.checkers['create'](
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
    print "[c] create tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)


    # == request ===============
    # gen
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.request(
            (create_tx['transaction']['outputs'][1],),
            None,
            None,
            clear_m, 
            hidden_m, 
            pub
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] request tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    request_tx = coconut.request(
        (create_tx['transaction']['outputs'][1],),
        None,
        None,
        clear_m, 
        hidden_m, 
        pub
    )
    solution = transaction_to_solution(request_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.contract.checkers['request'](
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
    print "[c] request tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)
    

    # == issue ===============
    # gen
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.issue(
            (request_tx['transaction']['outputs'][1],),
            None,
            None,
            sk[0],
            0
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] issue tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    issue_tx = coconut.issue(
        (request_tx['transaction']['outputs'][1],),
        None,
        None,
        sk[0],
        0
    )
    solution = transaction_to_solution(issue_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.contract.checkers['issue'](
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
    print "[c] issue tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)


    # == verify ===============
    # gen

    # issue t signatures
    old_request = request_tx['transaction']['outputs'][1]
    for i in range(t):
        transaction = coconut.issue(
            (old_request,),
            None,
            None,
            sk[i],
            i
        )
        old_request = transaction['transaction']['outputs'][0]

    # some crypto
    # ------------------------------------
    packet = loads(old_request)['sigs']
    (indexes, packed_enc_sigs) = zip(*packet)
    (h, packed_enc_epsilon) = zip(*packed_enc_sigs)
    enc_epsilon = [(unpackG1(params,x[0]), unpackG1(params,x[1])) for x in packed_enc_epsilon]
    dec_sigs = [(unpackG1(params,h[0]), elgamal_dec(params, priv, enc)) for enc in enc_epsilon]
    aggr = aggregate_th_sign(params, dec_sigs)
    aggr = randomize(params, aggr)
    packed_sig = (pack(aggr[0]),pack(aggr[1]))
    # ------------------------------------
              
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.verify(
            None,
            (create_tx['transaction']['outputs'][1],),
            (packed_sig,),
            clear_m,
            hidden_m
        )
        end_time = time.time()
        times.append((end_time-start_time)*1000)
    mean = numpy.mean(times)
    sd = numpy.std(times)
    print "[g] verify tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    # check
    verify_tx = coconut.verify(
        None,
        (create_tx['transaction']['outputs'][1],),
        (packed_sig,),
        clear_m,
        hidden_m
    )
    solution = transaction_to_solution(verify_tx)
    times = []
    for i in range(RUNS):
        start_time = time.time()
        coconut.contract.checkers['verify'](
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
    print "[c] verify tx\t{:.10f}\t\t{:.10f}\t{}".format(mean, sd, RUNS)

    '''
    print("\nTransactions:")
    print(create_tx)
    print(request_tx)
    print(issue_tx)
    print(verify_tx)
    '''

if __name__ == '__main__':
    main()
