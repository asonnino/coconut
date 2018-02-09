""" test authenticated bank transfer """

####################################################################
# imports
###################################################################
# general
from multiprocessing import Process
from hashlib import sha256
from binascii import hexlify, unhexlify
from json import dumps, loads
import time
import unittest
import requests
# cypto
from petlib.bn import Bn
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples.coconut import contract as coconut_contract
from chainspacecontract.examples import coconut
# coconut
from chainspacecontract.examples.coconut_util import pack, unpackG1, unpackG2
from chainspacecontract.examples.coconut_lib import setup, elgamal_keygen, mix_ttp_th_keygen
from chainspacecontract.examples.coconut_lib import elgamal_dec, aggregate_th_sign, randomize, sign, verify

# debug
from chainspacecontract.examples.coconut_lib import verify, show_mix_sign, mix_verify, prepare_mix_sign, mix_sign
from bplib.bp import BpGroup, G2Elem
import time

####################################################################
q = 5 # max number of messages
t, n = 2, 3 # threshold and total numbero of authorities
callback = 'hello.init' # id of the callback contract
params = setup(q) # system's parameters
clear_m = [1, 2] # messages for plaintext signature
hidden_m = [3, 4, 5] # messages for blind signature
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
sig = aggregate_th_sign(params, sigs)
#print(mix_verify(params, vvk, None, sig, None, [m]))
# ------------------------------------


class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):

        checker_service_process = Process(target=coconut_contract.run_checker_service)
        checker_service_process.start()
        time.sleep(0.1)

        try:

            ## create transaction
            transaction = coconut.init()

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/init', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

        finally:
            ## stop service
            checker_service_process.terminate()
            checker_service_process.join()

    def test_context(self):

        with coconut_contract.test_service():
            ## create transaction
            transaction = coconut.init()

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/init', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])



    # --------------------------------------------------------------
    # test create instance
    # --------------------------------------------------------------
    def test_create(self):
        with coconut_contract.test_service():

            ## create transaction
            # init
            init_transaction = coconut.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            transaction = coconut.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                vvk,
                sig
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/create', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test request
    # --------------------------------------------------------------
    def test_request(self):
        with coconut_contract.test_service():

            ## create transactions
            # init
            init_transaction = coconut.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            create_transaction = coconut.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                vvk,
                sig
            )
            instance = create_transaction['transaction']['outputs'][1]
            # request
            transaction = coconut.request(
                (instance,),
                None,
                None,
                clear_m, 
                hidden_m, 
                pub
            )

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/request', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

    # --------------------------------------------------------------
    # test issue
    # --------------------------------------------------------------
    def test_issue(self):
        with coconut_contract.test_service():

            ## create transactions
            # init
            init_transaction = coconut.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            create_transaction = coconut.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                vvk,
                sig
            )
            instance = create_transaction['transaction']['outputs'][1]
            # request
            request_transaction = coconut.request(
                (instance,),
                None,
                None,
                clear_m, 
                hidden_m, 
                pub
            )
            old_request = request_transaction['transaction']['outputs'][1]

            # issue a signatures
            transaction = coconut.issue(
                (old_request,),
                None,
                None,
                sk[0],
                0
            )
            old_request = transaction['transaction']['outputs'][0]

            ## submit transaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/issue', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            # issue the other t-1 signatures
            for i in range(1,t):
                transaction = coconut.issue(
                    (old_request,),
                    None,
                    None,
                    sk[i],
                    i
                )
                old_request = transaction['transaction']['outputs'][0]

            # some crypto - to show that this actually works
            # ------------------------------------
            packet = loads(old_request)['sigs']
            (indexes, packed_enc_sigs) = zip(*packet)
            (h, packed_enc_epsilon) = zip(*packed_enc_sigs)
            enc_epsilon = [(unpackG1(params,x[0]), unpackG1(params,x[1])) for x in packed_enc_epsilon]
            dec_sigs = [(unpackG1(params,h[0]), elgamal_dec(params, priv, enc)) for enc in enc_epsilon]
            aggr = aggregate_th_sign(params, dec_sigs)
            aggr = randomize(params, aggr)
            (kappa, proof_v) = show_mix_sign(params, vvk, hidden_m)
            print("\n\n=================== VERIFICATION ===================\n")
            print(mix_verify(params, vvk, kappa, aggr, proof_v, clear_m))
            print("\n====================================================\n\n")
            # ------------------------------------

    # --------------------------------------------------------------
    # test verify
    # --------------------------------------------------------------
    def test_verify(self):
        with coconut_contract.test_service():

            ## create transactions
            # init
            init_transaction = coconut.init()
            token = init_transaction['transaction']['outputs'][0]
            # create instance
            create_transaction = coconut.create(
                (token,),
                None,
                None,
                q,
                t,
                n,
                callback, 
                vvk,
                sig
            )
            instance = create_transaction['transaction']['outputs'][1]
            # request
            request_transaction = coconut.request(
                (instance,),
                None,
                None,
                clear_m, 
                hidden_m, 
                pub
            )
            old_request = request_transaction['transaction']['outputs'][1]

            # issue t signatures
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

            # verify signature
            start_time = time.time()
            transaction = coconut.verify(
                None,
                (instance,),
                (packed_sig,),
                clear_m,
                hidden_m
            )
            end_time = time.time(); print((end_time-start_time)*1000)

            ## submit t ransaction
            response = requests.post(
                'http://127.0.0.1:5000/' + coconut_contract.contract_name 
                + '/verify', json=transaction_to_solution(transaction)
            )
            self.assertTrue(response.json()['success'])

            print("\n\n=================== VERIFICATION ===================\n")
            print(transaction['transaction']['returns'][0])
            print("\n====================================================\n\n")


####################################################################
# main
###################################################################
if __name__ == '__main__':
    unittest.main()
