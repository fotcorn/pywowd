"""
002a          UNKNOWN
ec01          Packet type
01000000      Unknown, hardcoded
43e74cc4      seed
37e60f0d515c508853e77ac1b7dbdbaa    generated seed 1
510f137c3f0d2dbab10c0bf59fc2b2c6    generated seed 1
"""
import struct
from binascii import hexlify, unhexlify

from pywowd.opcodes import SMSG_AUTH_CHALLENGE
from pywowd.utils import int_to_bin

class AuthChallenge(object):
    
    seed = seed1 = seed2 = None
    
    def encode(self):
        size = 42
        op_code = SMSG_AUTH_CHALLENGE
        
        data = struct.pack('>H', size)
        data += struct.pack('<HI', op_code, 1)
        data += int_to_bin(self.seed)
        data += int_to_bin(self.seed1)
        data += int_to_bin(self.seed2)
        return data
        
        
if __name__ == '__main__':
    authc = AuthChallenge()
    authc.seed = 0xc44ce743
    authc.seed1 = 0xaadbdbb7c17ae75388505c510d0fe637
    authc.seed2 = 0xc6b2c29ff50b0cb1ba2d0d3f7c130f51
    print hexlify(authc.encode())
    print '002aec010100000043e74cc437e60f0d515c508853e77ac1b7dbdbaa510f137c3f0d2dbab10c0bf59fc2b2c6'
    