import binascii

def int_to_bin(longint):
    hexint = "%x" % longint
    if len(hexint) % 2 == 1:
        hexint = "0" + hexint
    return binascii.unhexlify(hexint)[::-1]

def bin_to_int(binary):
    return int(binascii.hexlify(binary[::-1]), 16)

def rc4crypt(data, key):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x,y = 0, 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))
    return ''.join(out)