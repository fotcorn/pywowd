import binascii

class RealmlistResponse:
    def encode(self):
        
        data = binascii.unhexlify("102900000000000100") # realmlist, size, unknown, 1 realm
        #data = data + binascii.unhexlify("010002") # pvp, online, color
        
        
        data = data + binascii.unhexlify("010001") # type, online, color

        
        
        data = data + binascii.unhexlify("666f74636f726e00") # realmname
        data = data + binascii.unhexlify("3132372e302e302e313a3830383500") # ip &port in ascii
        data = data + binascii.unhexlify("0000000000012c1000")
        return data
   
