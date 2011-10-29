import struct
import binascii

class LogonChallengeReqPacket:
    
    def decode(self, data):
        packet = struct.unpack('<bbh4sbbbh4s4s4siBBBBb', data[:34]) # sbbbhss
        self.command = packet[0]
        self.error = packet[1]
        self.packet_size = packet[2]
        self.game = packet[3].replace("\x00", "")[::-1]
        self.version1 = packet[4]
        self.version2 = packet[5]
        self.version3 = packet[6]
        self.build = packet[7]
        self.platform = packet[8].replace("\x00", "")[::-1]
        self.os = packet[9].replace("\x00", "")[::-1]
        self.country = packet[10][::-1]
        self.timezone_bias = packet[11]
        self.ip = str(packet[12]) + "." + str(packet[13]) + "." + str(packet[14]) + "." + str(packet[15])
        self.srp_I_len = packet[16]
        self.srp_I = data[34:34+self.srp_I_len]

if __name__ == '__main__':
    auth = LogonChallengeReqPacket()
    auth.decode(binascii.unhexlify("00082b00576f5700040100b736363878006e695700454465643c000000c0a802c80d41444d494e4953545241544f52"))
    print auth.__dict__    


