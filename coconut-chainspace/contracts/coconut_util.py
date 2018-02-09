from bplib.bp import G2Elem, G1Elem
from petlib.pack import encode, decode
from binascii import hexlify, unhexlify

def pet_pack(x):
    return hexlify(encode(x))

def pet_unpack(x):
    return decode(unhexlify(x))

def pack(x):
	return hexlify(x.export()).decode()

def unpackG1(params, x):
	G = params[0]
	return G1Elem.from_bytes(unhexlify(x.encode()), G)

def unpackG2(params, x):
	G = params[0]
	return G2Elem.from_bytes(unhexlify(x.encode()), G)

