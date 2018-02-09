""" test authenticated bank transfer """

####################################################################
# imports
###################################################################
# general
from multiprocessing import Process
from json            import dumps, loads
import time
import unittest
import requests
# chainspace
from chainspacecontract import transaction_to_solution
from chainspacecontract.examples.petition import contract as petition_contract
from chainspacecontract.examples import petition
# petlib
from chainspacecontract.examples.utils import key_gen as pet_keygen
from chainspacecontract.examples.utils import setup as pet_setup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.coconut_util import pet_pack, pet_unpack, pack, unpackG1, unpackG2
from chainspacecontract.examples.coconut_lib import setup as bp_setup
from chainspacecontract.examples.coconut_lib import ttp_th_keygen, elgamal_keygen, elgamal_dec
from chainspacecontract.examples.coconut_lib import prepare_blind_sign, blind_sign, aggregate_th_sign, randomize
from chainspacecontract.examples.coconut_lib import show_coconut_petition, coconut_petition_verify

# debug
import time


####################################################################
# authenticated bank transfer
####################################################################
# crypto parameters
t, n = 4, 5 # threshold and total numbero of authorities
bp_params = bp_setup() # bp system's parameters
(sk, vk, vvk) = ttp_th_keygen(bp_params, t, n) # signers keys

# petition parameters
UUID = Bn(1234)
options = ['YES', 'NO']
pet_params = pet_setup()
(priv_owner, pub_owner) = pet_keygen(pet_params)


class Test(unittest.TestCase):
    # --------------------------------------------------------------
    # test init
    # --------------------------------------------------------------
    def test_init(self):
        ## run service
        checker_service_process = Process(target=petition_contract.run_checker_service)
        checker_service_process.start()
        time.sleep(0.1)

        ## create transaction
        transaction = petition.init()

        ## submit transaction
        response = requests.post(
            'http://127.0.0.1:5000/' + petition_contract.contract_name 
            + '/init', json=transaction_to_solution(transaction)
        )
        self.assertTrue(response.json()['success'])

        ## stop service
        checker_service_process.terminate()
        checker_service_process.join()


    # --------------------------------------------------------------
    # test create petition
    # --------------------------------------------------------------
    def test_create_petition(self):
        ## run service
        checker_service_process = Process(target=petition_contract.run_checker_service)
        checker_service_process.start()
        time.sleep(0.1)

        ## create transaction
        # init
        init_transaction = petition.init()
        token = init_transaction['transaction']['outputs'][0]

        # initialise petition
        transaction = petition.create_petition(
            (token,),
            None,
            None,
            UUID,
            options,
            priv_owner,
            pub_owner,
            vvk
        )

        ## submit transaction
        response = requests.post(
            'http://127.0.0.1:5000/' + petition_contract.contract_name 
            + '/create_petition', json=transaction_to_solution(transaction)
        )
        self.assertTrue(response.json()['success'])

        ## stop service
        checker_service_process.terminate()
        checker_service_process.join()
 
    # --------------------------------------------------------------
    # test sign
    # --------------------------------------------------------------
    def test_sign(self):
        ## run service
        checker_service_process = Process(target=petition_contract.run_checker_service)
        checker_service_process.start()
        time.sleep(0.1)

        ## create transaction
        # init
        init_transaction = petition.init()
        token = init_transaction['transaction']['outputs'][0]

        # initialise petition
        create_petition_transaction = petition.create_petition(
            (token,),
            None,
            None,
            UUID,
            options,
            priv_owner,
            pub_owner,
            vvk
        )
        old_petition = create_petition_transaction['transaction']['outputs'][1]
        old_list = create_petition_transaction['transaction']['outputs'][2]

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

        # add signature to th petition
        start = time.time()
        transaction = petition.sign(
            (old_petition, old_list),
            None,
            (dumps([1, 0]),),
            priv_signer,
            sig,
            vvk
        )
        end = time.time()
        print((end-start)*1000)

        ## submit transaction
        response = requests.post(
            'http://127.0.0.1:5000/' + petition_contract.contract_name 
            + '/sign', json=transaction_to_solution(transaction)
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
