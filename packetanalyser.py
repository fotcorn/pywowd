import packet
from binascii import unhexlify


authPacketDef = [
	packet.Value("command", 1),
	packet.Value("error", 1),
	packet.Value("packetsize", 1),
	packet.Value("A", 32),
	packet.String("username", sizesize=1)]

#authPacket = packet.createPacket(authPacketDef)
#authPacket.error.setInt(0)
#authPacket.packetsize.setInt(50)
#authPacket.command.setHex("0x3F")
#authPacket.command.setInt()
#authPacket.A.setHex("3232323232323232323232323232323232323232323232323232323232323232")
#authPacket.username.setASCII("fritzli")

authPacket = packet.parsePacket(authPacketDef, unhexlify("010050323232323232323232323232323232323232323232323232323232323232323205464142496F"))

print authPacket.__dict__
