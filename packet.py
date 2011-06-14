class _PacketData:
	pass

class Packet:
	def parse(self, data):
		for k in self.__dict__:
			print k

class Byte:
	def __init__(self, size=1):
		self.size = size

class String:
	def __init__(self, sizesize=1):
		self.sizesize = sizesize


