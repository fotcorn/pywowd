import socket
from binascii import unhexlify as uhex
from binascii import hexlify

from packets.logonchallengereq import LogonChallengeReqPacket
from packets.logonchallengeresp import LogonChallengeRespPacket
from packets.logonproofreq import LogonProofReqPacket
from packets.logonproofresp import LogonProofRespPacket
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

connection.sendall(challenge_resp.encode())

# proof
data = connection.recv(8096)
proof_req = LogonProofReqPacket()
proof_req.decode(data)

auth.srp_A = proof_req.srp_A
auth.srp_M1 = proof_req.srp_M1
auth.crc = proof_req.crc

auth.calcM2()

proof_resp = LogonProofRespPacket()


while True:
    pass
