import socket
from binascii import unhexlify as uhex
from binascii import hexlify

from packets.logonchallengereq import LogonChallengeReqPacket
from packets.logonchallengeresp import LogonChallengeRespPacket
import auth

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 3724))
s.listen(1)

connection, address = s.accept()


# auth
data = connection.recv(8096)
challenge_req = LogonChallengeReqPacket()
challenge_req.decode(data)

print challenge_req.__dict__

# challenge
auth = auth.Auth()
auth.password = "administrator"
auth.username = "administrator"

auth.calcPasswordHash()
auth.calcSaltVerify()
auth.calcB()

challenge_resp = LogonChallengeRespPacket()
challenge_resp.error = 0
challenge_resp.unknownbyte = 0
challenge_resp.srp_B = auth.B
challenge_resp.srp_g = 7
challenge_resp.srp_N = auth.N
challenge_resp.srp_s = auth.salt
challenge_resp.unknown = uhex("e7f44ff2561eac9ab1bcf5a242c5c799")
challenge_resp.security = 0


packet = ""
packet = packet + uhex("000000") #command, error, unknown field
packet = packet + uhex("0" + ("%x" % auth.B))[::-1] # B
packet = packet + uhex("01") # g length
packet = packet + uhex("07") # g
packet = packet + uhex("20") # N length
packet = packet + uhex("%x" % auth.N)[::-1] # N
packet = packet + auth.salt[::-1] # s = salt
packet = packet + uhex("e7f44ff2561eac9ab1bcf5a242c5c799") # unknown data
packet = packet + uhex("00") # security flags

print hexlify(packet)
print hexlify(challenge_resp.encode())

#connection.sendall(packet)

# proof
data = connection.recv(8096)

auth.A = data[1:33]
auth.calcM2()


while True:
    pass
