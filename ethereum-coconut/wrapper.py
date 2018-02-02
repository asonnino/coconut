from bn128 import G1, G2, FQ
from bn128 import is_inf, eq, neg, add, multiply
from bn128 import curve_order, pairing


# ==================================================
# BpGroup
# ==================================================
class BpGroup():

	def __init__(self):
		self.g1 = G1Elem()
		self.g2 = G2Elem()
		self.o = Order()

	def gen1(self):
		return self.g1

	def gen2(self):
		return self.g2

	def order(self):
		return self.o

	def hashG1(self, sbin):
		# TODO
		return self.g1

	def pair(self, g1Elem, g2Elem):
		return pairing(g2Elem.g, g1Elem.g)


# ==================================================
# G1Elem
# ==================================================
class G1Elem:
	inf = multiply(G1, curve_order)

	def __init__(self, g=G1):
		self.g = g

	def __str__(self):
		return '(' + str(self.g[0]) + ',' + str(self.g[1]) + ')'

	def __add__(self, other):
		return G1Elem(add(self.g,other.g))

	def __radd__(self, other):
		return G1Elem(add(self.g,other.g))

	def __sub__(self, other):
		return G1Elem(add(self.g,neg(other.g)))

	def __mul__(self, other):
		return G1Elem(multiply(self.g,other))

	def __rmul__(self, other):
		return G1Elem(multiply(self.g,other))

	def __eq__(self, other):
		return eq(self.g,other.g)

	def __ne__(self, other):
		return not eq(self.g,other.g)

	def __copy__(self):
		return G1Elem()

	def isinf(self):
		return is_inf(self.g)

	def export(self):
		return bytes(self.__str__().encode())


# ==================================================
# G2Elem
# ==================================================
class G2Elem:
	inf = multiply(G2, curve_order)

	def __init__(self, g=G2):
		self.g = g

	def __str__(self):
		return '(' + str(self.g[0]) + ',' + str(self.g[1]) + ')'

	def __add__(self, other):
		return G2Elem(add(self.g,other.g))

	def __radd__(self, other):
		return G2Elem(add(self.g,other.g))

	def __sub__(self, other):
		return G2Elem(add(self.g,neg(other.g)))

	def __mul__(self, other):
		return G2Elem(multiply(self.g,other))

	def __rmul__(self, other):
		return G2Elem(multiply(self.g,other))

	def __eq__(self, other):
		return eq(self.g,other.g)

	def __ne__(self, other):
		return not eq(self.g,other.g)

	def __copy__(self):
		return G2Elem()

	def isinf(self):
		return is_inf(self.g)

	def export(self):
		return bytes(self.__str__().encode())
		

# ==================================================
# Order
# ==================================================
class Order():

	def __init__(self, o=curve_order):
		self.o = o

	def __str__(self):
		return 'Order'

	def __mod__(self, other):
		return self.o % other

	def __rmod__(self, other):
		return other % self.o

	def __floordiv__(self, other):
		return self.o // other

	def __rfloordiv__(self, other):
		return other // self.o

	def __sub__(self, other):
		return self.o - other

	def __rsub__(self, other):
		return other - self.o

	def random(self):
		return 10
		#rng = SystemRandom()
		#return rng.randint(0, self.o)


