import packet
from binascii import unhexlify

class AuthPacket(packet.Packet):
	command = packet.Byte(size=1)
	error = packet.Byte(size=1)
	packetSize = packet.Byte(size=1)
	A = packet.Byte(size=32)
	userName = packet.String(sizesize=1)


authPacket = AuthPacket().parse(unhexlify("010050323232323232323232323232323232323232323232323232323232323232323205464142496F"))



#print authPacket.command
#print authPacket.username


