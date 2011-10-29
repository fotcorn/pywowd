import binascii

def long_to_bin(longint):
    hexint = "%x" % longint
    if len(hexint) % 2 == 1:
        hexint = "0" + hexint
    return binascii.unhexlify(hexint)