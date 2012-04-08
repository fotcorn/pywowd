import binascii

def int_to_bin(longint):
    hexint = "%x" % longint
    if len(hexint) % 2 == 1:
        hexint = "0" + hexint
    return binascii.unhexlify(hexint)[::-1]

def bin_to_int(binary):
    return int(binascii.hexlify(binary[::-1]), 16)