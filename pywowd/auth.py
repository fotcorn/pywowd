import hashlib

from pywowd.utils import bin_to_int, int_to_bin
import binascii

class Auth:
    username = ""
    password = ""
    passwordHash = ""
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

    def calcSaltVerify(self):
        self.s = binascii.unhexlify("%x" % 80214272189838780128605308367486581597145816548177813688284808124909330286083)[::-1]
        
        #self.s = os.urandom(64)
        sha = hashlib.sha1()
        sha.update(self.s) # reverse salt
        sha.update(self.passwordHash)
        x = bin_to_int(sha.digest())
        self.v = pow(self.g, x, self.N)
        

    def calcB(self):
        #self.b = int(hexlify(os.urandom(19)), 16)
        #self.b = int("9DF4D983AC5E403A7F9CDF40FE1C34FA2EC7AF", 16)
        
        self.b = 3552787550811435226985428356693069762706615077
        
        gmod = pow(self.g, self.b, self.N)
        self.B = ((self.v * 3) + gmod) % self.N

    def calcM2(self):
        sha = hashlib.sha1()
        sha.update(int_to_bin(self.A))
        sha.update(int_to_bin(self.B))
        
        u = bin_to_int(sha.digest())
        self.S = pow(self.A * pow(self.v, u, self.N), self.b, self.N)
        
        t = int_to_bin(self.S)
        t1 = list()
        for i in range(0, 32, 2):
            t1.append(t[i])
        sha = hashlib.sha1()
        sha.update("".join(t1))
        
        vK = list(range(0, 40))
        
        # fill even vK entries [0], [2] etc.
        for i in range(0, 20):
            vK[i * 2] = sha.digest()[i]
            
        for i in range(0, 16):
            t1[i] = t[i * 2 + 1]
            
        sha = hashlib.sha1()
        sha.update("".join(t1))
        
        # fill uneven vK entries [1], [3] etc.
        for i in range(0, 20):
            vK[i * 2 + 1] = sha.digest()[i]
            
        self.K = bin_to_int("".join(vK))
        
        sha = hashlib.sha1()
        sha.update(int_to_bin(self.N))
        N_sha = sha.digest()
        sha = hashlib.sha1()
        sha.update(int_to_bin(self.g))
        g_sha = sha.digest()
        
        hash = list()
        for i in range(0, 20):
            hash.append(int_to_bin(bin_to_int(N_sha[i]) ^ bin_to_int(g_sha[i])))
            
        t3 = "".join(hash)
        
        sha = hashlib.sha1()
        sha.update(self.username)
        t4 = sha.digest()
        
        # calculated M1
        sha = hashlib.sha1()
        sha.update(t3)
        sha.update(t4)
        sha.update(self.s)
        sha.update(int_to_bin(self.A))
        sha.update(int_to_bin(self.B))
        sha.update(int_to_bin(self.K))
        M = sha.digest()
        
        if bin_to_int(M) == self.M1:
            print "Password correct"
        
        # calculate M2
        sha = hashlib.sha1()
        sha.update(int_to_bin(self.A))
        sha.update(M)
        sha.update(int_to_bin(self.K))
        self.M2 = sha.digest()
        
        
if __name__ == '__main__':
    auth = Auth()
    auth.username = "ADMINISTRATOR"
    auth.A = 32392226636057736569178298570200726764378903089572035718146014074628746469686
    auth.B = 39477995497094999596777037250542921589225449793199811220997955316523550273175
    auth.v = 17459918643670693210059420188370715679876585876282611281718504289092941609328
    auth.N = 62100066509156017342069496140902949863249758336000796928566441170293728648119
    auth.b = 5294621419232486107292813785331503792670248187
    auth.S = 9730816514788708246368885035945444809585353141117486926833255596885657893262
    auth.u = 1338803149889234015817804178382685056276146714235
    auth.s = int_to_bin(80214272189838780128605308367486581597145816548177813688284808124909330286083)
    

    auth.calcM2()
    