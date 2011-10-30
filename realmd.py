import socket
from binascii import unhexlify as uhex

from packets.logon.challenge_request import ChallengeRequest
from packets.logon.challenge_response import ChallengeResponse
from packets.logon.proof_request import ProofRequest
from packets.logon.proof_response import ProofResponse
from packets.logon.realmlist_response import RealmlistResponse

import auth



s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('', 3724))
s.listen(1)

connection, address = s.accept()


# auth
data = connection.recv(4096)

challenge_req = ChallengeRequest()
challenge_req.decode(data)

# challenge
auth = auth.Auth()
auth.password = "administrator"
auth.username = "administrator"

auth.calcPasswordHash()
auth.calcSaltVerify()
auth.calcB()

challenge_resp = ChallengeResponse()
challenge_resp.error = 0
challenge_resp.unknownbyte = 0
challenge_resp.srp_B = auth.B
challenge_resp.srp_g = 7
challenge_resp.srp_N = auth.N
challenge_resp.srp_s = auth.s
challenge_resp.unknown = uhex("e7f44ff2561eac9ab1bcf5a242c5c799")
challenge_resp.security = 0

connection.sendall(challenge_resp.encode())

# proof
data = connection.recv(4096)
proof_req = ProofRequest()
proof_req.decode(data)

auth.A = proof_req.srp_A
auth.M1 = proof_req.srp_M1
auth.crc = proof_req.crc

auth.calcM2()

proof_resp = ProofResponse()
proof_resp.srp_M2 = auth.M2

connection.sendall(proof_resp.encode())

realmlist_respone = RealmlistResponse()

while True:
    data = connection.recv(4096)
    connection.sendall(realmlist_respone.encode())

