# -*- coding: utf-8 -*-

from tabulate import tabulate
import binascii


def UnlockUICRImage(path):
    """Helper function to unlock the UICR image to reflash later"""
    fp = open(path, 'rb+')
    fp.seek(4)
    fp.write(0xFFFFFFFF.to_bytes(4, byteorder='little'))
    fp.close()


def YesOrNo(question):
    reply = str(input(question + ' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return YesOrNo('please enter y/n')


def GetAscii(data):
    """Helper function to pretty print any ASCII chars in byte array"""
    ascii = ''
    for c in data:
        if 32 <= c <= 126:
            ascii = ascii + str(chr(c))
        else:
            ascii = ascii + '.'
    return ascii


def printChipInfo(chip_info):
    print('')
    print(tabulate(chip_info.items(), tablefmt='psql'))
    print('')


def printHexDump(data, start_address):
    print('+------------+-------------+------+')
    for i in (range(0, len(data), 4)):
        print('| 0x{:08X} | {} | {} |'.format(start_address + i, ' '.join(['{:02x}'.format(x) for x in data[i:i+4]]), GetAscii(data[i:i+4])))
    print('+------------+-------------+------+\n')


def printECB(data):
    print('AES Electronic Codebook mode encryption')
    print('Key:         {}'. format(binascii.hexlify(data[0:16]).decode()))
    print('Cleartext:   {}'. format(binascii.hexlify(data[16:32]).decode()))
    print('Ciphertext:  {}'. format(binascii.hexlify(data[32:48]).decode()))