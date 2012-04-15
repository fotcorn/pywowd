from binascii import unhexlify
import struct
import SocketServer

from pywowd.packets.world.auth_challenge import AuthChallenge
from pywowd.header_encrypt import HeaderCrypt
from pywowd import opcodes
from pywowd.handlers.register import handlers

# tcp.flags.push == 1


class WorldSocket(SocketServer.BaseRequestHandler):
    
    def setup(self):
        f = open('sessionid.txt', 'r')
        session_id = unhexlify(f.read())
        f.close()
        self.crypt = HeaderCrypt(session_id)
        
    def handle(self):
        print 'Connected to Client'
        self.connected()
        
        while True:
            data = self.request.recv(4096)
            self.data_recived(data)
    
    def send(self, opcode, payload, encrypt=True):
        print " - Sending Packet with OpCode %x and length %s" % (opcode, len(payload) + 2)
        header = struct.pack('>H', len(payload) + 2)
        header += struct.pack('<H', opcode)
        
        if encrypt == True:
            header = self.crypt.encrypt(header)
        
        self.request.sendall(header + payload)
            
    def connected(self):
        challenge = AuthChallenge()
        challenge.seed = 0xc44ce743
        challenge.seed1 = 0xaadbdbb7c17ae75388505c510d0fe637
        challenge.seed2 = 0xc6b2c29ff50b0cb1ba2d0d3f7c130f51        
        self.send(opcodes.SMSG_AUTH_CHALLENGE, challenge.encode(), False)
            
    def data_recived(self, data):
        if struct.unpack('<I', data[2:6])[0] == opcodes.CMSG_AUTH_SESSION:
            header = (42, opcodes.CMSG_AUTH_SESSION)
        else:
            header = self.crypt.decrypt_header(data[:6])
        
        if header[1] in handlers:
            handler = handlers[header[1]]
            print "- Handling Packet with OpCode %x and length %s by %s.%s" % (header[1], header[0], handler.__module__, handler.__name__)
            handler(self, data[6:])
        else:
            print "+ Unknown Packet with OpCode %x and length %s" % (header[1], header[0])

SocketServer.TCPServer.allow_reuse_address = True
server = SocketServer.TCPServer(('localhost', 8085), WorldSocket)
server.serve_forever()

