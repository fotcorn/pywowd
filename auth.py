import hashlib
from binascii import hexlify, unhexlify

from utils import bin_to_int, int_to_bin

class Auth:
    username = ""
    password = ""
    passwordHash = ""
    salt = ""
    v = ""
    b = 0
    B = 0
    A = 0
    M2 = 0

    # hardcoded strings
    N = int("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7", 16)
    g = int("07", 16)


    def calcPasswordHash(self):
        self.username = self.username.upper()
        self.password = self.password.upper()
        
        sha = hashlib.sha1()
        sha.update(self.username)
        sha.update(":")
        sha.update(self.password)
        self.passwordHash = sha.digest()
        print "pwhash: " + sha.hexdigest()

    def calcSaltVerify(self):
        s = unhexlify('B157AB4DCB6E2AD1DFEDA51F2D18E91AF12D665111F9990BB902B30C80B6C603')
        #self.salt = os.urandom(64)
        self.salt = s
        sha = hashlib.sha1()
        sha.update(self.salt[::-1]) # reverse salt
        sha.update(self.passwordHash)
        x =  bin_to_int(sha.digest()[::-1])
        self.v = pow(self.g, x, self.N)

    def calcB(self):
        #self.b = int(hexlify(os.urandom(19)), 16)
        self.b = int("9DF4D983AC5E403A7F9CDF40FE1C34FA2EC7AF", 16)
        gmod = pow(self.g, self.b, self.N)
        self.B = ((self.v * 3) + gmod) % self.N

    def calcM2(self):
        """ required vars:
        A, B, v, N, b
        """
        
        sha = hashlib.sha1()
        sha.update(int_to_bin(self.A))
        sha.update(int_to_bin(self.B))
        
        u = bin_to_int(sha.digest())
        self.S = pow(self.A * pow(self.v, u, self.N), self.b, self.N)
        
        """"t = int_to_bin(self.S)
        t1 = list()
        for i in range(0,16):
            t1[i] = t[i*2]"""
        
        
if __name__ == '__main__':
    auth = Auth()
    
    auth.calcM2()
    
    
    


    
    
    
    