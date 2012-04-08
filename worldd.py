import socket
import binascii

from pywowd.packets.world.auth_challenge import AuthChallenge

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 8085))
s.listen(1)


s.accept()
connection, address = s.accept()

print "connected"

challenge = AuthChallenge()
challenge.seed = 0xc44ce743
challenge.seed1 = 0xaadbdbb7c17ae75388505c510d0fe637
challenge.seed2 = 0xc6b2c29ff50b0cb1ba2d0d3f7c130f51

connection.sendall(challenge.encode())

while True:
    data = connection.recv(4096)
    print "recv"
    print binascii.hexlify(data)
