import hashlib
from binascii import hexlify, unhexlify
import os

class Auth:
    username = ""
    password = ""
    passwordHash = ""
    salt = ""
    verify = ""
    b = ""
    B = ""
    A = ""
    M2 = ""

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
        x =  int(hexlify(sha.digest()[::-1]), 16)
        self.verify = pow(self.g, x, self.N)

    def calcB(self):
        #self.b = int(hexlify(os.urandom(19)), 16)
        self.b = int("9DF4D983AC5E403A7F9CDF40FE1C34FA2EC7AF", 16)
        gmod = pow(self.g, self.b, self.N)
        B = ((self.verify * 3) + gmod) % self.N
        self.B = unhexlify("%x" % B)

    def calcM2(self):
        pass

# verify codes:
# pw hash: a34b29541b87b7e4823683ce6c7bf6ae68beaaac

#v = unhexlify("20363BAF9E0748743B43BB7E9DB34A648BFEA5BB0D25739262550C37D5C9096D")
#v: '2699F6B83C6DFABC2E1E1DEFEF14628D16F7B3D3416D5BAA951B0C3EC3FB7970'
# 
#x: '0E08664C68A89E9DD2B7E17A08506F9417B01248'
