import socket
from binascii import unhexlify as uhex
from binascii import hexlify

from packets.logon.challenge_request import ChallengeRequest
from packets.logon.challenge_response import ChallengeResponse
from packets.logon.proof_request import ProofRequest
from packets.logon.proof_response import ProofResponse

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

data = connection.recv(4096)
print hexlify(data)

"""

b: 3552787550811435226985428356693069762706615077
auth.A = 20786166616285150936945641957357500816582650181458829850018473554299598773284
auth.B = 60252366686859016907562177805391517456839259990270867763174675335285595359215
auth.v = 17459918643670693210059420188370715679876585876282611281718504289092941609328
auth.N = 62100066509156017342069496140902949863249758336000796928566441170293728648119
auth.b = 3552787550811435226985428356693069762706615077
auth.S = 19006572672777162759658146598870473190751811781236988660854174754208489806773
auth.u = 231658895428635000729769887560106445350741127792
auth.s = 80214272189838780128605308367486581597145816548177813688284808124909330286083
K = 1534563802275733359233150492891297758466599443734434606514493711501798706186100865402252191870236
t3 = 957738555058196676454969243856207669001771318237
t4 = 633177174871819402933449143504090799582347380005
s = 80214272189838780128605308367486581597145816548177813688284808124909330286083
M = 1137309772963296485203196658204195843622854576297
M2 = 443961021635455728087010113625189863876437014953

challenge1 = "00082b00576f5700040202d138363878006e695700454465643c0000007f0000010d41444d494e4953545241544f52"
challenge2 = "000000efc70afa2d0adce4d59f892aa76725b538c18ad27efeb7b053406e158ba13585010720b79b3e2a87823cab8f5ebfbf8eb10108535006298b5badbd5b53e1895e644b8903c6b6800cb302b90b99f91151662df11ae9182d1fa5eddfd12a6ecb4dab57b185cc22efe45f18c04dd541e2255768a500"
proof1 = "01249cb9029c694197d40686c76cb2ac4637cb296d0bedec9ba01c969faa8df42da9c8b5da42a2c5cf6cb82a5fb5242222e9bb36c7b45ff4acaa965ae8a369302fe4134591dd822ed50000"
proof2 = "0100a9f978a03aa9222e8fdd4db9ca5d5f4b96e6c34d00008000000000000000"

"""