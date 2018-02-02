# petlib import-export
from petlib.pack import encode, decode
from binascii import hexlify, unhexlify

##########################################
# utilities
def pack(x):
    return hexlify(encode(x)).decode('utf-8')

def unpack(x):
    return decode(unhexlify(x.encode('utf-8')))