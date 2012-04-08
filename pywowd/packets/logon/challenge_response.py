import struct
import binascii

from pywowd.utils import int_to_bin

class ChallengeResponse:
    
    def encode(self):
        B = int_to_bin(self.srp_B)
        g = int_to_bin(self.srp_g)
        N = int_to_bin(self.srp_N)
        data = struct.pack("<bbb32s", 0, self.error, self.unknownbyte, B)
        data = data + struct.pack("<b" + str(len(g)) + "s", len(g), g)
        data = data + struct.pack("<b" + str(len(N)) + "s", len(N), N)
        data = data + struct.pack("<32s16sb", self.srp_s, self.unknown, self.security)
        return data

if __name__ == '__main__':
    auth = ChallengeResponse()
    auth.error = 0
    auth.unknownbyte = 0
    auth.srp_B = int("a0715a053ec5646250e12e6aad48b747509fdb60e1e2c22fe521f63283416d20", 16)
    auth.srp_g = 7
    auth.srp_N = int("b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b89", 16)
    auth.srp_s = int("03c6b6800cb302b90b99f91151662df11ae9182d1fa5eddfd12a6ecb4dab57b1", 16)
    auth.unknown = binascii.unhexlify("01e72082cebc0003eea61fc5a74c96ab")
    auth.security = 0

    encoded = auth.encode()

    print binascii.hexlify(encoded)
    print encoded == binascii.unhexlify("000000a0715a053ec5646250e12e6aad48b747509fdb60e1e2c22fe521f63283416d20010720b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b8903c6b6800cb302b90b99f91151662df11ae9182d1fa5eddfd12a6ecb4dab57b101e72082cebc0003eea61fc5a74c96ab00")

