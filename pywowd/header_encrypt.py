import hmac
from hashlib import sha1
from binascii import unhexlify, hexlify

from pywowd.utils import rc4crypt

session_key = unhexlify('09AC58CDDC4637EF4F9B6711779178ED3960F1E839BCC9FDFC4B65D68A50B429BDB8D2CBE3FF1340')

SERVER_ENCRYPT_KEY = unhexlify('CC98AE04E897EACA12DDC09342915357')
SERVER_DECRYPT_KEY = 0xC2B3723CC6AED9B5343C53EE2F4367CE





hash = hmac.new(key=SERVER_ENCRYPT_KEY, msg=session_key[::-1], digestmod=sha1)
encrypt_hash = hash.digest()



header1_enc = '119a870a'
# length: 13 -> 000D
# opcode: 1EE -> 01EE
header2_dec = unhexlify('000DEE01')
header2 = 0x02e84118
header3 = 0xe493456c



data = rc4crypt('\0' * 1024 + header2_dec, encrypt_hash)
print hexlify(data[1024:])
print header1_enc




# length: 13
# type: 0x1ee