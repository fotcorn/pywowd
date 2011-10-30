import binascii

class RealmlistResponse:
    def encode(self):
        return binascii.unhexlify("102900000000000100010002666f74636f726e003132372e302e302e313a38303835000000000000012c1000")
    
   
