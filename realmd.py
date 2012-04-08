import socket
from binascii import hexlify, unhexlify
import threading

from pywowd.packets.logon.challenge_request import ChallengeRequest
from pywowd.packets.logon.challenge_response import ChallengeResponse
from pywowd.packets.logon.proof_request import ProofRequest
from pywowd.packets.logon.proof_response import ProofResponse
from pywowd.packets.logon.realmlist_response import RealmlistResponse
from pywowd.auth import Auth

class RealmDaemonThread(threading.Thread):
    
    def run(self):
        data = self.connection.recv(4096)
        
        challenge_req = ChallengeRequest()
        challenge_req.decode(data)
        
        # challenge
        auth = Auth()
        auth.password = "admin"
        auth.username = "admin"
        
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
        challenge_resp.unknown = unhexlify("e7f44ff2561eac9ab1bcf5a242c5c799")
        challenge_resp.security = 0
        
        self.connection.sendall(challenge_resp.encode())
        
        # proof
        data = self.connection.recv(4096)
        proof_req = ProofRequest()
        proof_req.decode(data)
        
        auth.A = proof_req.srp_A
        auth.M1 = proof_req.srp_M1
        auth.crc = proof_req.crc
        
        auth.calcM2()
        
        proof_resp = ProofResponse()
        proof_resp.srp_M2 = auth.M2
        
        self.connection.sendall(proof_resp.encode())
        
        realmlist_respone = RealmlistResponse()
        
        while True:
            self.connection.recv(4096)
            self.connection.sendall(realmlist_respone.encode())

if __name__ == '__main__':
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('', 3724))
    s.listen(1)
        
    while True:
        connection, address = s.accept()
        thread = RealmDaemonThread()
        thread.connection = connection
        thread.daemon = True
        thread.start()
    