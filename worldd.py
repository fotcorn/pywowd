import socket
from binascii import hexlify, unhexlify
import struct
import SocketServer

from pywowd.packets.world.auth_challenge import AuthChallenge
from pywowd.header_encrypt import HeaderCrypt
from pywowd import opcodes

# tcp.flags.push == 1


class WorldSocket(SocketServer.BaseRequestHandler):
    def handle(self):
        print "connected"
        
        challenge = AuthChallenge()
        challenge.seed = 0xc44ce743
        challenge.seed1 = 0xaadbdbb7c17ae75388505c510d0fe637
        challenge.seed2 = 0xc6b2c29ff50b0cb1ba2d0d3f7c130f51
        
        self.request.sendall(challenge.encode())
        
        # CMSG_AUTH_SESSION, not very interesting...
        self.request.recv(4096)
        
        f = open('sessionid.txt', 'r')
        session_id = unhexlify(f.read())
        f.close()
        
        crypt = HeaderCrypt(session_id)
        
        def create_packet(size, opcode, payload):
            header = struct.pack('>H', size)
            header += struct.pack('<H', opcode)
            header = crypt.encrypt(header)
            return header + payload
        
        packet = create_packet(13, opcodes.SMSG_AUTH_RESPONSE, unhexlify('0c00000000000000000000'))
        self.request.sendall(packet)
        
        packet = create_packet(190, opcodes.SMSG_ADDON_INFO, unhexlify('0201000000000000020100000000000002010000000000000201000000000000020100000000000002010000000000000201000000000000020100000000000002010000000000000201000000000000020100000000000002010000000000000201000000000000020100000000000002010000000000000201000000000000020100000000000002010000000000000201000000000000020100000000000002010000000000000201000000000000020100000000000000000000'))
        self.request.sendall(packet)
        
        packet = create_packet(6, opcodes.SMSG_CLIENTCACHE_VERSION, unhexlify('00000000'))
        self.request.sendall(packet)
        
        packet = create_packet(34, opcodes.SMSG_TUTORIAL_FLAGS, unhexlify('0000000000000000000000000000000000000000000000000000000000000000'))
        self.request.sendall(packet)
        
        # CMSG_READY_FOR_ACCOUNT_DATA_TIMES
        header = self.request.recv(4096)[:6]
        print hexlify(crypt.decrypt(header))

        packet = create_packet(23, opcodes.SMSG_ACCOUNT_DATA_TIMES, unhexlify('6989814f0115000000000000000000000000000000'))
        self.request.sendall(packet)
        
        # CMSG_CHAR_ENUM
        header = self.request.recv(4096)[:6]
        print hexlify(crypt.decrypt(header))
        
        # CMSG_REALM_SPLIT
        header = self.request.recv(4096)[:6]
        print hexlify(crypt.decrypt(header))
        
        # SMSG_CHAR_ENUM
        packet = create_packet(3, opcodes.SMSG_CHAR_ENUM, unhexlify('00'))
        self.request.sendall(packet)
        
        # SMSG_REALM_SPLIT
        packet = create_packet(19, opcodes.SMSG_REALM_SPLIT, unhexlify('ffffffff0000000030312f30312f303100'))
        self.request.sendall(packet)
        
        while True:
            pass

server = SocketServer.TCPServer(('localhost', 8085), WorldSocket)
server.serve_forever()

