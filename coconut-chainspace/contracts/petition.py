""" 
	A simple smart contract illustarting an e-petition.
"""


####################################################################
# imports
####################################################################
# general
from hashlib import sha256
from json    import dumps, loads
# petlib
from chainspacecontract.examples.utils import setup as pet_setup
from petlib.ecdsa import do_ecdsa_sign, do_ecdsa_verify
# coconut
from chainspacecontract.examples.coconut_util import pet_pack, pet_unpack, pack, unpackG1, unpackG2
from chainspacecontract.examples.coconut_lib import setup as bp_setup
from chainspacecontract.examples.coconut_lib import show_coconut_petition, coconut_petition_verify
# chainspace
from chainspacecontract import ChainspaceContract

# debug
import time

## contract name
contract = ChainspaceContract('petition')


####################################################################
# methods
####################################################################
# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------
@contract.method('init')
def init():
    return {
        'outputs': (dumps({'type' : 'PToken'}),),
    }

# ------------------------------------------------------------------
# create petition
# ------------------------------------------------------------------
@contract.method('create_petition')
def create_petition(inputs, reference_inputs, parameters, UUID, options, priv_owner, pub_owner, vvk):
    # inital score
    scores = [0 for _ in options]

    # pack vvk
    packed_vvk = (pack(vvk[0]),pack(vvk[1]),pack(vvk[2]))

    # new petition object
    new_petition = {
        'type' : 'PObject',
        'UUID' : pet_pack(UUID), # unique ID of the petition
        'owner' : pet_pack(pub_owner), # entity creating the petition
        'verifier' : packed_vvk, # entity delivering credentials to participate to the petition
        'options' : options, # the options to sign
        'scores' : scores # the signatures per option
    }

    # ID lists
    signed_list = {
        'type' : 'PList',
        'list' : []
    }

    # signature
    pet_params = pet_setup()
    hasher = sha256()
    hasher.update(dumps(new_petition).encode('utf8'))
    sig = do_ecdsa_sign(pet_params[0], priv_owner, hasher.digest())

    # return
    return {
        'outputs': (inputs[0], dumps(new_petition), dumps(signed_list)),
        'extra_parameters' : (pet_pack(sig),)
    }

# ------------------------------------------------------------------
# sign
# ------------------------------------------------------------------
@contract.method('sign')
def sign(inputs, reference_inputs, parameters, priv_signer, sig, vvk):
	# ini petition, list and parameters
	old_petition = loads(inputs[0])
	new_petition = loads(inputs[0])
	old_list = loads(inputs[1])
	new_list = loads(inputs[1])
	new_values = loads(parameters[0])

	# update petition values
	for i in range(0,len(new_values)):
		new_petition['scores'][i] = old_petition['scores'][i] + new_values[i]

	# prepare showing of credentials
	UUID = pet_unpack(old_petition['UUID'])
	bp_params = bp_setup()
	(kappa, nu, proof_v) = show_coconut_petition(bp_params, vvk, priv_signer, UUID)
	#print(coconut_petition_verify(bp_params, vvk, kappa, sig, proof_v, UUID, nu))

	# update spent list
	new_list['list'].append(pack(nu))

	# pack sig
	packed_sig = (pack(sig[0]),pack(sig[1]))

	# return
	return {
		'outputs': (dumps(new_petition),dumps(new_list)),
		'extra_parameters' : (packed_sig, pack(kappa), pack(nu), pet_pack(proof_v))
	}



####################################################################
# checker
####################################################################
# ------------------------------------------------------------------
# check petition's creation
# ------------------------------------------------------------------
@contract.checker('create_petition')
def create_petition_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve petition
        petition = loads(outputs[1])
        # retrieve ID list
        spent_list = loads(outputs[2])
        # retrieve parameters
        sig = pet_unpack(parameters[0])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 3 or len(returns) != 0:
            return False 

        # check types
        if loads(inputs[0])['type'] != 'PToken' or loads(outputs[0])['type'] != 'PToken': return False
        if petition['type'] != 'PObject' or spent_list['type'] != 'PList': return False

        # check fields
        petition['UUID'] # check presence of UUID
        petition['verifier'] # check presence of verifier
        options = petition['options']
        scores = petition['scores'] 
        pub_owner = pet_unpack(petition['owner'])
        if len(options) < 1 or len(options) != len(scores): return False

        # check initalised scores
        if not all(init_score==0 for init_score in scores): return False

        # verify signature
        pet_params = pet_setup()
        hasher = sha256()
        hasher.update(outputs[1].encode('utf8'))
        if not do_ecdsa_verify(pet_params[0], pub_owner, sig, hasher.digest()): return False

        # verify that the spent list is empty
        if spent_list['list']: return False

        # otherwise
        return True

    except (KeyError, Exception):
        return False


# ------------------------------------------------------------------
# check add score
# ------------------------------------------------------------------
@contract.checker('sign')
def sign_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve petition
        old_petition = loads(inputs[0])
        new_petition = loads(outputs[0])
        # retrieve ID list
        old_list = loads(inputs[1])
        new_list = loads(outputs[1])
        # retrieve parameters
        bp_params = bp_setup()
        new_values = loads(parameters[0])
        packed_sig = parameters[1]
        sig = (unpackG1(bp_params, packed_sig[0]), unpackG1(bp_params, packed_sig[1]))
        kappa = unpackG2(bp_params, parameters[2])
        nu = unpackG1(bp_params, parameters[3])
        proof_v = pet_unpack(parameters[4])

        # check format
        if len(inputs) != 2 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if new_petition['type'] != 'PObject' or new_list['type'] != 'PList': return False      

        # check format & consistency with old object
        UUID = pet_unpack(new_petition['UUID'])
        options = new_petition['options']
        packed_vvk = new_petition['verifier']
        scores = new_petition['scores']
        if old_petition['UUID'] != new_petition['UUID']: return False
        if len(old_petition['owner']) != len(new_petition['owner']): return False
        if len(old_petition['options']) != len(new_petition['options']): return False
        if old_petition['verifier'] != new_petition['verifier']: return False

        # check new values
        if sum(new_values) != 1: return False
        for i in range(len(scores)):
            if scores[i] != old_petition['scores'][i] + new_values[i]: return False
            if new_values[i] != 0 and new_values[i] != 1: return False

        # check spent list
        packed_nu = parameters[3]
        if (packed_nu in old_list['list']) or (new_list['list'] != old_list['list'] + [packed_nu]):
            return False

        # verify signature and nu's correctness
        vvk = (unpackG2(bp_params,packed_vvk[0]), unpackG2(bp_params,packed_vvk[1]), unpackG2(bp_params,packed_vvk[2]))
        if not coconut_petition_verify(bp_params, vvk, kappa, sig, proof_v, UUID, nu): return False
  
        # otherwise
        return True

    except (KeyError, Exception): 
        return False


####################################################################
# main
####################################################################
if __name__ == '__main__':
    contract.run()



####################################################################