""" test authenticated bank transfer """

####################################################################
# imports
###################################################################
# general
from multiprocessing import Process
from json import dumps, loads
from hashlib import sha256
from binascii import hexlify, unhexlify
import time
import unittest
import requests
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples.tumbler import contract as tumbler_contract
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


####################################################################
# authenticated bank transfer
####################################################################
# crypto parameters
t, n = 4, 5 # threshold and total numbero of authorities
bp_params = bp_setup() # bp system's parameters
(sk, vk, vvk) = ttp_th_keygen(bp_params, t, n) # signers keys

# tumbler parameter
ID = 10 # random ID
merchant_addr = 'merchant_addr' # merchant address

# some crypto
# ------------------------------------
packed_vvk = (pack(vvk[0]),pack(vvk[1]),pack(vvk[2]))
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
#print(verify(bp_params, vvk, m, auth_sig))



class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):
        ## run service
        checker_service_process = Process(target=tumbler_contract.run_checker_service)
        checker_service_process.start()
        time.sleep(0.1)

        ## create transaction
        transaction = tumbler.init()

        ## submit transaction
        response = requests.post(
            'http://127.0.0.1:5000/' + tumbler_contract.contract_name 
            + '/init', json=transaction_to_solution(transaction)
        )
        self.assertTrue(response.json()['success'])

        ## stop service
        checker_service_process.terminate()
        checker_service_process.join()

    # --------------------------------------------------------------
    # test create tumbler
    # --------------------------------------------------------------
    def test_create_tumbler(self):
        ## run service
        checker_service_process = Process(target=tumbler_contract.run_checker_service)
        checker_service_process.start()
        time.sleep(0.1)

        ## create transaction
        # init
        init_transaction = tumbler.init()
        token = init_transaction['transaction']['outputs'][0]

        # initialise petition
        transaction = tumbler.create_tumbler(
            (token,),
            None,
            None,
            vvk,
            auth_sig
        )

        ## submit transaction
        response = requests.post(
            'http://127.0.0.1:5000/' + tumbler_contract.contract_name
            + '/create_tumbler', json=transaction_to_solution(transaction)
        )
        self.assertTrue(response.json()['success'])

        ## stop service
        checker_service_process.terminate()
        checker_service_process.join()

    # --------------------------------------------------------------
    # test redeem
    # --------------------------------------------------------------
    def test_redeem(self):
        ## run service
        checker_service_process = Process(target=tumbler_contract.run_checker_service)
        checker_service_process.start()
        time.sleep(0.1)

        ## create transaction
        # init
        init_transaction = tumbler.init()
        token = init_transaction['transaction']['outputs'][0]

        # initialise petition
        create_transaction = tumbler.create_tumbler(
            (token,),
            None,
            None,
            vvk,
            auth_sig
        )
        old_list = create_transaction['transaction']['outputs'][1]

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

        # add signature to th petition
        transaction = tumbler.redeem(
            (old_list,),
            None,
            (dumps(ID),dumps(merchant_addr)),
            sig,
            vvk,
        )

        ## submit transaction
        response = requests.post(
            'http://127.0.0.1:5000/' + tumbler_contract.contract_name 
            + '/redeem', json=transaction_to_solution(transaction)
        )
        self.assertTrue(response.json()['success'])

        ## stop service
        checker_service_process.terminate()
        checker_service_process.join()

   
####################################################################
# main
###################################################################
if __name__ == '__main__':
    unittest.main()
