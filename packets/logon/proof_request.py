import struct
import binascii

from utils import bin_to_int

class ProofRequest:
    def decode(self, data):
        packet = struct.unpack('<b32s20s20sbb', data)
        self.command = packet[0]
        self.srp_A = bin_to_int(packet[1])
        self.srp_M1 = bin_to_int(packet[2])
        
        #self.srp_A = int(binascii.hexlify(packet[1]), 16)
        #self.srp_M1 = int(binascii.hexlify(packet[2]), 16)
        
        
        self.crc = packet[3]
        self.number_of_keys = packet[4]

if __name__ == '__main__':
    proof = ProofRequest()
    proof.decode(binascii.unhexlify("01f11fa15d99eaee901ab51a7af86c45e6d93d6316dc61dae55db9b277618d9466aab71d3eca2baf1400275528ccfae57419be78dc903f45db14921959b77f898333033defd38e8a3c0000"))
    print binascii.hexlify(proof.srp_A)
    print binascii.hexlify(proof.srp_M1)
    print binascii.hexlify(proof.crc)

