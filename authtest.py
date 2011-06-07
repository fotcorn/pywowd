from auth import Auth
from binascii import hexlify, unhexlify

auth = Auth()
auth.password = "administrator"
auth.username = "administrator"

auth.calcPasswordHash()
auth.calcSaltVerify()

