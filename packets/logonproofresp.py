import struct
import binascii

class LogonProofRespPacket:
    def encode(self):
        data = struct.pack('<bb20s10s', 1, self.error, self.srp_M2, binascii.unhexlify("00008000000000000000")) # unknown data
        return data
    
    
if __name__ == '__main__':
    proof = LogonProofRespPacket()
    proof.error = 0
    proof.srp_M2 = binascii.unhexlify("c531573757e189970962fa890eb2a304e4b56b9f")
    
    print proof.encode() == binascii.unhexlify("0100c531573757e189970962fa890eb2a304e4b56b9f00008000000000000000")
    
    
    
    