""" 
	Coin tumbler.
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
from petlib.bn import Bn
# coconut
from chainspacecontract.examples.coconut_util import pet_pack, pet_unpack, pack, unpackG1, unpackG2
from chainspacecontract.examples.coconut_lib import setup as bp_setup, verify
from chainspacecontract.examples.coconut_lib import show_coconut_petition, coconut_petition_verify
# chainspace
from chainspacecontract import ChainspaceContract

## contract name
contract = ChainspaceContract('tumbler')


####################################################################
# methods
####################################################################
# ------------------------------------------------------------------
# init
# ------------------------------------------------------------------
@contract.method('init')
def init():
    return {
        'outputs': (dumps({'type' : 'TToken'}),),
    }

# ------------------------------------------------------------------
# create tumbler
# ------------------------------------------------------------------
@contract.method('create_tumbler')
def create_tumbler(inputs, reference_inputs, parameters, vvk, sig):
    # pack vvk
    packed_vvk = (pack(vvk[0]),pack(vvk[1]),pack(vvk[2]))

    # ID lists
    spent_list = {
        'type' : 'TList',
        'list' : [],
        'vvk'  : packed_vvk
    }

    # return
    return {
        'outputs': (inputs[0], dumps(spent_list)),
        'extra_parameters' : (pet_pack(sig),)
    }

# ------------------------------------------------------------------
# redeem
# ------------------------------------------------------------------
@contract.method('redeem')
def redeem(inputs, reference_inputs, parameters, sig, vvk):
    # ini petition, list and parameters
    old_list = loads(inputs[0])
    new_list = loads(inputs[0])
    ID = loads(parameters[0])

    # update spent list
    new_list['list'].append(ID)

    # pack sig
    packed_sig = (pack(sig[0]),pack(sig[1]))

    # return
    return {
        'outputs': (dumps(new_list),),
        'extra_parameters' : (packed_sig,)
    }



####################################################################
# checker
####################################################################
# ------------------------------------------------------------------
# check tumbler's creation
# ------------------------------------------------------------------
@contract.checker('create_tumbler')
def create_tumbler_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve ID list
        spent_list = loads(outputs[1])
        # retrieve vvk & sig
        packed_vvk = spent_list['vvk']
        sig = pet_unpack(parameters[0])

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 2 or len(returns) != 0:
            return False 

        # check types
        if loads(inputs[0])['type'] != 'TToken' or loads(outputs[0])['type'] != 'TToken': return False
        if spent_list['type'] != 'TList': return False

        # verify that the spent list is empty
        if spent_list['list']: return False

        # verify signature
        bp_params = bp_setup()
        hasher = sha256()
        hasher.update(outputs[1].encode('utf8'))
        m = Bn.from_binary(hasher.digest())
        vvk = (unpackG2(bp_params,packed_vvk[0]), unpackG2(bp_params,packed_vvk[1]), unpackG2(bp_params,packed_vvk[2]))
        if not verify(bp_params, vvk, m, sig): return False

        # otherwise
        return True

    except (KeyError, Exception):
        return False


# ------------------------------------------------------------------
# check add score
# ------------------------------------------------------------------
@contract.checker('redeem')
def redeem_checker(inputs, reference_inputs, parameters, outputs, returns, dependencies):
    try:
        # retrieve ID list
        old_list = loads(inputs[0])
        new_list = loads(outputs[0])
        # retrieve parameters
        bp_params = bp_setup()
        ID = loads(parameters[0])
        merchant_addr = loads(parameters[1])
        packed_sig = parameters[2]
        sig = (unpackG1(bp_params, packed_sig[0]), unpackG1(bp_params, packed_sig[1]))

        # check format
        if len(inputs) != 1 or len(reference_inputs) != 0 or len(outputs) != 1 or len(returns) != 0:
            return False 

        # check types
        if new_list['type'] != 'TList': return False      

        # check format & consistency with old object
        packed_vvk = new_list['vvk']
        if new_list['vvk'] != new_list['vvk']: return False

        # check spent list
        if (ID in old_list['list']) or (new_list['list'] != old_list['list'] + [ID]):
            return False

        # verify signature and nu's correctness
        vvk = (unpackG2(bp_params,packed_vvk[0]), unpackG2(bp_params,packed_vvk[1]), unpackG2(bp_params,packed_vvk[2]))
        hasher = sha256()
        hasher.update(parameters[0].encode('utf8'))
        hasher.update(parameters[1].encode('utf8'))
        m = Bn.from_binary(hasher.digest())
        if not verify(bp_params, vvk, m, sig): return False
  
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