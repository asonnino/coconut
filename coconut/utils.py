""" Utils supporting coconut """
from bplib.bp import BpGroup


# ==================================================
# El-Gamal encryption scheme
# ==================================================
def elgamal_keygen(params):
   """ generate an El Gamal key pair """
   (G, o, g1, hs, g2, e) = params
   d = o.random()
   gamma = d * g1
   return (d, gamma)

def elgamal_enc(params, gamma, m, h):
    """ encrypts the values of a message (h^m) """
    (G, o, g1, hs, g2, e) = params
    k = o.random()
    a = k * g1
    b = k * gamma + m * h
    return (a, b, k)

def elgamal_dec(params, d, c):
    """ decrypts the message (h^m) """
    (G, o, g1, hs, g2, e) = params
    (a, b) = c
    return b - d*a


# ==================================================
# polynomial utilities
# ==================================================
def poly_eval(coeff, x):
	""" evaluate a polynomial defined by the list of coefficient coeff at point x """
	return sum([coeff[i] * (x ** i) for i in range(len(coeff))])

def lagrange_basis(indexes, o, x=0):
    """ generates all lagrange basis polynomials """
    l = []
    for i in indexes:
        numerator, denominator = 1, 1
        for j in indexes:
            if j != i:
                numerator = (numerator * (x - j)) % o
                denominator = (denominator * (i - j)) % o
        l.append((numerator * denominator.mod_inverse(o)) % o)
    return l


# ==================================================
# other
# ==================================================
def ec_sum(list):
	""" sum EC points list """
	ret = list[0]
	for i in range(1,len(list)):
		ret = ret + list[i]
	return ret


