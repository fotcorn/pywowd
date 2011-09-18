import struct
import binascii

class LogonChallengeRespPacket:
    
    structure = ""

    def encode(self):
        data = struct.pack("<bbb32s", self.command, self.error, self.unknownbyte, self.srp_B)
        data = data + struct.pack("<b" + str(len(self.srp_g)) + "s", len(self.srp_g), self.srp_g)
        data = data + struct.pack("<b" + str(len(self.srp_N)) + "s", len(self.srp_N), self.srp_N)
        data = data + struct.pack("<32s16sb", auth.srp_s, auth.unknown, auth.security)
        return data

if __name__ == '__main__':
    auth = LogonChallengeRespPacket()
    auth.command = 0
    auth.error = 0
    auth.unknownbyte = 0
    auth.srp_B = binascii.unhexlify("a0715a053ec5646250e12e6aad48b747509fdb60e1e2c22fe521f63283416d20")
    auth.srp_g = binascii.unhexlify("07")
    auth.srp_N = binascii.unhexlify("b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b89")
    auth.srp_s = binascii.unhexlify("03c6b6800cb302b90b99f91151662df11ae9182d1fa5eddfd12a6ecb4dab57b1")
    auth.unknown = binascii.unhexlify("01e72082cebc0003eea61fc5a74c96ab")
    auth.security = 0

    encoded = auth.encode()

    print binascii.hexlify(encoded)
    print encoded == binascii.unhexlify("000000a0715a053ec5646250e12e6aad48b747509fdb60e1e2c22fe521f63283416d20010720b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b8903c6b6800cb302b90b99f91151662df11ae9182d1fa5eddfd12a6ecb4dab57b101e72082cebc0003eea61fc5a74c96ab00")

