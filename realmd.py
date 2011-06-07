import socket
from binascii import unhexlify as uhex
from binascii import hexlify



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 3724))
s.listen(1)

connection, address = s.accept()


# auth
data = connection.recv(8096)
usernamesize = ord(data[33:34])
user = data[35:35 + usernamesize]

# challenge
packet = ""
packet = packet + uhex("000000") #command, error, unknown field
B = uhex("12dc45ee8c34ac728d559361eae61770e472b3be82dece0d566799f33b135406")
packet = packet + B # B
packet = packet + uhex("0107") # g length, g
packet = packet + uhex("20") # N length
N = uhex("b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b89")
packet = packet + N # N
packet = packet + uhex("51860bc283f58a07dab5866cd26ef5a29b0819c6e92747966cbe01feaf2fcdaf") # s = salt
packet = packet + uhex("e7f44ff2561eac9ab1bcf5a242c5c799") # unknown data
packet = packet + uhex("00") # security flags

connection.sendall(packet)

data = connection.recv(8096)

# proof
A = data[1:33]
B



connection.sendall(packet)


data = connection.recv(8096)
print hexlify(data)
while 1:
    pass
connection.close()
