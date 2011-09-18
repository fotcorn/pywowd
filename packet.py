

class Value:
	def __init__(self, name, size):
		self.name = name
		self.size = size

class String:
	def __init__(self, name, sizesize):
		self.name = name
		self.sizesize = sizesize

class Packet:
	def serialize(self):
		pass


def parsePacket(packetdef, data):
	packet = Packet()
	offset = 0
	for field in packetdef:
		if isinstance(field, Value):
			packet.__dict__[field.name] = 1
		elif isinstance(field, String):
			packet.__dict__[field.name] = 1
	return packet
