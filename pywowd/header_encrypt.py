import hmac
import struct
from hashlib import sha1
from binascii import unhexlify
from M2Crypto.RC4 import RC4

SERVER_ENCRYPT_KEY = unhexlify('CC98AE04E897EACA12DDC09342915357')
SERVER_DECRYPT_KEY = unhexlify('C2B3723CC6AED9B5343C53EE2F4367CE')


class HeaderCrypt(object):
    
    def __init__(self, session_key):
        hash = hmac.new(key=SERVER_ENCRYPT_KEY, msg=session_key[::-1], digestmod=sha1)
        self.encrypter = RC4()
        self.encrypter.set_key(hash.digest())
        self.encrypter.update('\0' * 1024)
        
        hash = hmac.new(key=SERVER_DECRYPT_KEY, msg=session_key[::-1], digestmod=sha1)
        self.decrypter = RC4()
        self.decrypter.set_key(hash.digest())
        self.decrypter.update('\0' * 1024)

    def decrypt_header(self, header):
        decrypted_header = self.decrypter.update(header)
        size = struct.unpack('>H', decrypted_header[:2])[0]
        opcode = struct.unpack('<I', decrypted_header[2:6])[0]
        return (size, opcode)

    def encrypt(self, data):
        return self.encrypter.update(data)
