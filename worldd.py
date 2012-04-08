import socket
from binascii import hexlify, unhexlify
import struct
import SocketServer

from pywowd.packets.world.auth_challenge import AuthChallenge
from pywowd.header_encrypt import HeaderCrypt
from pywowd import opcodes




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
        
        
        data =  self.request.recv(4096)
        print hexlify(data)
        
        while True:
            pass


server = SocketServer.TCPServer(('localhost', 8085), WorldSocket)
server.serve_forever()

