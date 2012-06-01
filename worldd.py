from binascii import unhexlify, hexlify
import struct
import SocketServer

#from pywowd.packets.world.auth_challenge import AuthChallenge
from pywowd.header_encrypt import HeaderCrypt
from pywowd import opcodes
#from pywowd.handlers.register import handlers

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
        print " - Sending Packet with OpCode %x and length %s:" % (opcode, len(payload) + 2)
        header = struct.pack('<HI', len(payload) + 4, opcode)
                
        if encrypt == True:
            header = self.crypt.encrypt(header)
        
        print '   ' + hexlify(header + payload)
        
        self.request.sendall(header + payload)
            
    def connected(self):
        self.request.sendall(unhexlify('3000') + 'WORLD OF WARCRAFT CONNECTION - SERVER TO CLIENT' + unhexlify('00'))
        """
        challenge = AuthChallenge()
        challenge.seed = 0xc44ce743
        challenge.seed1 = 0xaadbdbb7c17ae75388505c510d0fe637
        challenge.seed2 = 0xc6b2c29ff50b0cb1ba2d0d3f7c130f51        
        self.send(opcodes.SMSG_AUTH_CHALLENGE, challenge.encode(), False)
        """
        
    def data_recived(self, data):
        if 'WORLD OF WARCRAFT CONNECTION' in data:
            self.send(opcodes.SMSG_AUTH_CHALLENGE, unhexlify('2074a610372c0fec8a727bf3adf4211646059628fb4058388f35598c5441161401f2947eaf'), False)
            
            
            """
            3bd6a1f0b272179d4f2bed7b0b6f88cca2c98628c5558aadd7037abcdf82f821019ae28234
            3df4bc46b26ca07f311a5fa5b8fc3a043ed8ad088b7ff72ec6deb0c233de658f012dd109bf
            2074a610372c0fec8a727bf3adf4211646059628fb4058388f35598c5441161401f2947eaf
            
            """
            
            
            
            return
        
        if struct.unpack('<I', data[2:6])[0] == opcodes.CMSG_AUTH_SESSION:
            print 'len:' + str(len(data)) + ' ' + str(struct.unpack('<H', data[:2]))
            header = (42, opcodes.CMSG_AUTH_SESSION)
        else:
            print 'len: ' + str(len(data)) + ' ' + hex(len(data))
            print 'unencrypted header:' + hexlify(data[:6])
            header = self.crypt.decrypt_header(data[:6])
        """
        if header[1] in handlers:
            handler = handlers[header[1]]
            print "- Handling Packet with OpCode %x and length %s by %s.%s" % (header[1], header[0], handler.__module__, handler.__name__)
            handler(self, data[6:])
        else:
        """
        #print "+ Unknown Packet with OpCode %x and length %s" % (header[1], header[0])

SocketServer.TCPServer.allow_reuse_address = True
server = SocketServer.TCPServer(('localhost', 8085), WorldSocket)
server.serve_forever()

