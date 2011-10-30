import socket
import binascii

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 8085))
s.listen(1)


s.accept()
connection, address = s.accept()

print "connected"

data = connection.recv(4096)
print "recv"
print binascii.hexlify(data)


while True:
    pass