# -*- coding: utf-8 -*-

from . import utils
from . import nordic
from . import dbg

import coloredlogs # https://coloredlogs.readthedocs.io
import logging
import argparse
import os

# define a global logger
logger = logging.getLogger(__name__)


def main():
    parser = argparse.ArgumentParser(prog='nrfsec',
                        description='perform security related tasks on nRF51 targets through SWD interface',
                        usage='nrfsec <command> [<args>]')
    parser.add_argument('-f', '--frequency',
                    help='frequency to run the SWD interface (default 4 MHz)',
                    type=int, default=4000000)

    parser.add_argument('-v', '--verbose', action='store_true',
                    help='increase output verbosity',)

    subparsers = parser.add_subparsers(title='supported subcommands', dest='command')

    # parser - info
    parser_info = subparsers.add_parser('info', help='display chip information')
    parser_info.add_argument('-d', '--delay', type=int,
                    help='delay after reset before reading info (to initialize RAM and peripherals)')
    parser_info.add_argument('-m', '--maxsearch',
                        help='Maximum space to search for gadgets, starting at the reset vector',
                        default='0x1000')

    # parser - erase
    parser_erase = subparsers.add_parser('erase', help='perform a complete erase')
    parser_erase.add_argument('-m', '--maxsearch',
                        help='Maximum space to search for gadgets, starting at the reset vector',
                        default='0x1000')

    # parser - restore
    parser_restore = subparsers.add_parser('restore', help='restore specific images to an unlocked chip')
    parser_restore.add_argument('-u', '--uicr',
                        help='UICR image file to restore',
                        default=os.getcwd() + '/fw/0x10001000_0x10001400_UICR.bin')
    parser_restore.add_argument('-r', '--rom',
                        help='ROM image file to restore',
                        default=os.getcwd() + '/fw/0x00000000_0x00040000_ROM.bin')
    parser_restore.add_argument('-s', '--skipverify', action='store_true',
                        help='skip image verification steps')

    # parser - read
    parser_read = subparsers.add_parser('read', help='read memory contents to outfile')
    parser_read.add_argument('-o', '--outfile',
                        help='File to store memory contents',
                        default='dump.bin')
    parser_read.add_argument('-m', '--maxsearch',
                        help='Maximum space to search for gadgets, starting at the reset vector',
                        default='0x1000')
    parser_read.add_argument('--skipverify', action='store_true',
                    help='skip image verification steps')
    parser_read.add_argument('-d', '--delay', type=int,
                        help='Delay time after boot before reading memory')
    address_group = parser_read.add_mutually_exclusive_group()
    address_group.add_argument('-s', '--start',
                        help='address to begin reading memory')
    parser_read.add_argument('-e', '--end',
                        help='address to stop reading memory')
    address_group.add_argument('-a', '--all', action='store_true',
                        help='Dump all memory as discovered in FICR register starting @ 0x00000000')

    # parser - unlock
    parser_unlock = subparsers.add_parser('unlock', help='unlock the device if locked')
    parser_unlock.add_argument('-m', '--maxsearch',
                    help='Maximum space to search for gadgets, starting at the reset vector',
                    default='0x1000')
    parser_unlock.add_argument('-d', '--directory',
                    help='Directory to store the recovered firmware',
                    default=os.getcwd() + '/fw')
    parser_unlock.add_argument('--skipverify', action='store_true',
                    help='skip image verification steps')
    # parser - lock
    subparsers.add_parser('lock', help='lock the device if unlocked')

    args = parser.parse_args()

    # logging setup
    if args.verbose:
        coloredlogs.install(level='DEBUG', datefmt='%H:%M:%S',
                            fmt='%(asctime)s: %(levelname)s - %(message)s')
    else:
        coloredlogs.install(level='INFO', datefmt='%H:%M:%S',
                            fmt='%(asctime)s: %(levelname)s - %(message)s')

    sub_commands = ['info', 'erase', 'restore', 'read', 'unlock', 'lock']
    if args.command not in sub_commands:
        logger.info('please specify a subcommand: {}'.format(sub_commands))
        exit()

    # connect to ST-Link, required for all commands
    logger.info('Connecting to debug interface @ {}Hz'.format(args.frequency))
    dev = dbg.DeviceInterface(args.frequency)

    # commands unaffected by lock state
    if args.command == 'erase':
        if dev.EraseAll():
            logger.info('target erased')
            exit()
        else:
            logger.info('unable to erase target')

    if dev.isLocked():
        logger.debug('target memory is locked')
        if args.command == 'lock':
            logger.info('target is already locked')
            exit()

        if args.command == 'restore':
            logger.info('target is locked, perform unlock before restoring')
            exit()

        r_gadget = dev.SearchReadGadget(int(args.maxsearch, 0))

        if r_gadget:
            if args.command == 'info':
                if args.delay:
                    dev.Delay(args.delay)
                dev.Dumpinfo(r_gadget)
                utils.printChipInfo(dev.chip_info)
                if args.verbose:
                    print('Factory Information Configuration Registers (FICR)')
                    utils.printHexDump(dev.ficr, nordic.NRF_FICR_BASE)
                    print('User Information Configuration Registers (UICR)')
                    utils.printHexDump(dev.uicr, nordic.NRF_UICR_BASE)
                if 0x3FFFFFFF > int(dev.chip_info['ECB -> ECBDATAPTR'], 0) > 0x20000000:
                    utils.printECB(dev.GetECB(r_gadget))
                if 0x20000000 < int(dev.chip_info['CCM -> CNFPTR'], 0) < 0x3FFFFFFF:
                    pass

            if args.command == 'read':
                if args.delay:
                    dev.Delay(args.delay)
                if args.all:
                    dev.Dumpinfo(r_gadget)
                    dev.ReadAll(os.getcwd() + '/fw', args.skipverify, r_gadget)
                elif args.start is not None and args.end is not None:
                    if int(args.start, 0) < int(args.end, 0):
                        dev.DumpToFile(args.outfile, int(args.start, 0), int(args.end, 0), r_gadget)
                    else:
                        logger.error('End address cannot begin before start address')
                        exit()
                else:
                    logger.error('You must supply a start and end address to read')
                    exit()

            if args.command == 'unlock':
                dev.Dumpinfo(r_gadget)
                if dev.VolatileUnlock(r_gadget, args.directory, args.skipverify):
                    logger.info('Unlocking procedure was successful')
                    dev.cortex_m.reset()
                    exit()
                else:
                    logger.info('Unlocking procedure was unsuccessful')
                    exit()
        else:
            logger.info('no read gadget found, exitting')
            exit()
    # unlocked
    else:
        logger.debug('target memory is unlocked')
        if args.command == 'lock':
            dev.LockTarget()

        if args.command == 'unlock':
            logger.info('target is already unlocked proceed with other commands')
            exit()

        if args.command == 'restore':
            if not os.path.isfile(args.rom):
                logger.error('ROM file {} not found\n'
                             'specify the -u and -r filename for the UICR and ROM files respectivily'.format(args.rom))
                exit()
            if not os.path.isfile(args.uicr):
                logger.error('UICR file {} not found:\n'
                             'specify the -u and -r filename for the UICR and ROM files respectivily'.format(args.uicr))
                exit()

            utils.UnlockUICRImage(args.uicr)
            dev.RestoreImage(args.rom, nordic.ROM_START)

            if not args.skipverify:
                if not dev.VerifyImage(args.rom, nordic.ROM_START, os.path.getsize(args.rom)):
                    logger.info('failed to verify writing {} to the target'.format(args.rom))
                    exit()
            dev.RestoreImage(args.uicr, nordic.NRF_UICR_BASE)
            if not args.skipverify:
                if not dev.VerifyImage(args.uicr, nordic.NRF_UICR_BASE, os.path.getsize(args.uicr)):
                    logger.info('failed to verify writing {} to the target'.format(args.uicr))
                    exit()
            logger.info('Target memory has been restored')
            dev.cortex_m.nodebug()
            exit()

        if args.command == 'info':
            dev.Dumpinfo(args.delay)
            utils.printChipInfo(dev.chip_info)
            if args.verbose:
                print('Factory Information Configuration Registers (FICR)')
                utils.printHexDump(dev.ficr, nordic.NRF_FICR_BASE)
                print('User Information Configuration Registers (UICR)')
                utils.printHexDump(dev.uicr, nordic.NRF_UICR_BASE)
            # these values must point to RAM or they are uninitialized
            if 0x20000000 < int(dev.chip_info['ECB -> ECBDATAPTR'], 0) < 0x3FFFFFFF:
                (dev.GetECB())
            if 0x20000000 < int(dev.chip_info['CCM -> CNFPTR'], 0) < 0x3FFFFFFF:
                pass

        if args.command == 'read':
            if args.delay:
                dev.Delay(args.delay)
            if args.all:
                dev.Dumpinfo()
                dev.ReadAll(os.getcwd() + '/fw', args.skipverify)
            elif args.start is not None and args.end is not None:
                if int(args.start, 0) < int(args.end, 0):
                    dev.DumpToFile(args.outfile, int(args.start, 0), int(args.end, 0))
                else:
                    logger.error('End address cannot begin before start address')
                    exit()
            else:
                logger.error('You must supply a start and end address to read')
                exit()

if __name__ == '__main__':
    main()
