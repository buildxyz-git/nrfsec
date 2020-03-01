# -*- coding: utf-8 -*-i


from .gadget import ReadGadget, WriteGadget
from . import utils
from . import nordic

import swd 	# https://github.com/cortexm/pyswd
import os
import logging
from tqdm import tqdm
from time import sleep

logger = logging.getLogger(__name__)


class DeviceInterface:
    """Class to handle interactions with the debug interface and SoC"""
    dev = None
    cortex_m = None
    reset_vector = None
    stack_pointer_init = None
    start_address = None
    end_address = None
    gp_regs_list = {'R0', 'R1', 'R2', 'R3', 'R4', 'R5', 'R6', 'R7', 'R8', 'R9', 'R10', 'R11', 'R12'}
    regs = {'LR': 0, 'MSP': 0, 'PC': 0, 'PSP': 0, 'PSR': 0, 'R0': 0, 'R1': 0,
            'R10': 0, 'R11': 0, 'R12': 0, 'R2': 0, 'R3': 0, 'R4': 0, 'R5': 0,
            'R6': 0, 'R7': 0, 'R8': 0, 'R9': 0, 'SP': 0}
    chip_info = {}
    uicr = bytearray()
    ficr = bytearray()

    def __init__(self, freq):
        try:
            self.dev = swd.Swd(swd_frequency=freq)
            self.cortex_m = swd.CortexM(self.dev)
            logger.info('Device found: {}'.format(self.dev.get_version()))
            logger.debug('Target Voltage: {} volts'.format(self.dev.get_target_voltage()))
            logger.debug('IDCODE: {}'.format(hex(self.dev.get_idcode())))

        except swd.stlink.usb.NoDeviceFoundException:
            logger.error('No debug interface detected')
            exit()
        except swd.stlink.usb.StlinkUsbException:
            logger.error('USB Error: Try reconnecting STLink')
            exit()
        except swd.stlink.StlinkException:
            logger.error('Could not connect to target, ensure the target is powered')
            exit()

    def isLocked(self):
        """Check if target is locked, True is returned if unable to read from the Reset vector address"""
        data = self.dev.get_mem32(0x00000004)
        if data == 0x00000000:
            return True
        else:
            return False

    def Unlock(self, write_gadget, read_gadget):
        """Magcal function that does not work because you can't write to the UICR without a full erase"""
        write_gadget.Write32(self, nordic.NVMC_CONFIG, 0x00000001)
        write_gadget.Write32(self, nordic.RBPCONF, 0xFFFFFFFF)
        if read_gadget.Read32(self, nordic.RBPCONF) == 0xFFFFFFFF:
            return True
        return False

    def SetAllRegs(self, set_value):
        """Set all general purpose registers to set_value"""
        for reg in self.gp_regs_list:
            try:
                self.cortex_m.set_reg(reg, set_value)
            except swd.stlink.StlinkException:
                logger.error("STLink write verification error")
                exit()

    def CheckGPRegsForValue(self, value):
        """Check all general purpose registers for value"""
        # Remove general purpose registers
        gp_dict = {key: self.regs[key] for key in self.regs if key not in ['SP', 'PC', 'LR', 'MSP', 'PSP', 'PSR']}
        for reg in gp_dict.keys():
            if gp_dict[reg] == value:
                return reg
        else:
            return False

    def GetReadDstReg(self, address):
        """Check for destination register, given an gadget address"""
        # 0x00000000 -> intial_sp location
        self.SetAllRegs(0x00000000)
        self.cortex_m.set_reg('PC', address)
        self.cortex_m.step()
        self.regs = self.cortex_m.get_reg_all()
        return self.CheckGPRegsForValue(self.stack_pointer_init)

    def GetReadSrcReg(self, address, regs):
        """Given and address and a list of registers to check, look for source register"""
        # Search for source register
        for reg in regs:
            # set all theother registers to something other than initial_sp 
            self.SetAllRegs(0x00000004)
            self.cortex_m.set_reg(reg, 0x00000000)
            self.cortex_m.set_reg('PC', address)
            self.cortex_m.step()
            self.regs = self.cortex_m.get_reg_all()
            if self.CheckGPRegsForValue(self.stack_pointer_init):
                return reg
        return False

    def GetWriteSrcReg(self, address, read_gadget):
        """Given an address, and a read gadget, check for write source register"""
        # 0x20000000 -> IRAM base on cortex-m cores, no harm in writing 0x20000000 @ 0x20000000 right?
        self.SetAllRegs(0x20000000)
        self.cortex_m.set_reg('PC', address)
        self.cortex_m.step()
        # use read_gadget to dump memory @0x20000000
        data = read_gadget.Read32(self, 0x20000000)
        if data == 0x20000000:
            # we may have a write gadget here, lets check each register
            for reg in self.gp_regs_list:
                self.SetAllRegs(0x20000000)
                self.cortex_m.set_reg('PC', address)
                self.cortex_m.set_reg(reg, 0xDEADBEEF)
                self.cortex_m.step()
                data = read_gadget.Read32(self, 0x20000000)
                if data == 0xDEADBEEF:
                    return reg
        return False

    def GetWriteDstReg(self, address, read_gadget, write_gadget):
        """Given an address, and a read gadget, check for write destination register"""
        # We have already found the gadget's src register prior to calling this method
        for reg in self.gp_regs_list:
            self.SetAllRegs(0x20000004)
            self.cortex_m.set_reg(reg, 0x20000000)
            self.cortex_m.set_reg(write_gadget.src_reg, 0xCAFEBABE)
            self.cortex_m.set_reg('PC', address)
            self.cortex_m.step()
            data = read_gadget.Read32(self, 0x20000000)
            if data == 0xCAFEBABE:
                return reg
        return False

    def SearchReadGadget(self, max_search):
        """Search memory for a read gadget and return it, otherwise False"""
        read_gadget = ReadGadget()
        # Reset halt for a static dump
        self.cortex_m.reset_halt()

        if self.cortex_m.is_halted():
            # store reset vector but add one as this is a Thumb address
            self.reset_vector = self.cortex_m.get_reg('PC') + 1
            logger.debug('Reset vector address found: 0x{:08X}'
                        .format(self.reset_vector))
            self.stack_pointer_init = self.cortex_m.get_reg('SP')
            logger.debug('Stack pointer initialized at address: 0x{:08X}'
                        .format(self.stack_pointer_init))
        else:
            logger.error('Failed to halt target')
            exit()

        logger.info('Searching for a read gadget @  0x{:08X} for {} bytes'
                    .format(self.reset_vector, max_search))

        # set PC to reset vector where we can expect some code and search max 4096 bytes
        for address in range(self.reset_vector, (self.reset_vector + max_search), 2):
            reg = self.GetReadDstReg(address)
            if reg:
                logger.debug('Candidate gadget found @ 0x{:08X}'.format(address))
                logger.debug('Destination register -> {}'. format(reg))
                read_gadget.address = address
                read_gadget.dst_reg = reg
                s_reg = self.GetReadSrcReg(address, self.gp_regs_list)
                if s_reg:
                    logger.debug('Source register -> {}'. format(s_reg))
                    read_gadget.src_reg = s_reg
                    # verify valid read gadget
                    data = read_gadget.Read32(self, 0x00000004)
                    if data == self.reset_vector:
                        logger.info('Read gadget located: 0x{:08X} -> LDR {}, [{}]'
                                    .format(address, read_gadget.dst_reg, read_gadget.src_reg))
                        return read_gadget
                else:
                    logger.debug('No source register found, continuing search')
        return False

    def SearchWriteGadget(self, read_gadget, max_search):
        """Search for a write gadget and return it else False"""
        write_gadget = WriteGadget()
        logger.info('Searching for a write gadget @ 0x{:08X} for {} bytes'
                    .format(self.reset_vector, max_search))
        # set PC to reset vector where we can expect some code and search max 4096 bytes
        for address in range(self.reset_vector, (self.reset_vector + max_search), 2):
            s_reg = self.GetWriteSrcReg(address, read_gadget)
            if s_reg:
                logger.debug('Candidate gadget found @ 0x{:08X}'.format(address))
                logger.debug('Source register -> {}'. format(s_reg))
                write_gadget.address = address
                write_gadget.src_reg = s_reg
                d_reg = self.GetWriteDstReg(address, read_gadget, write_gadget)
                if d_reg:
                    # verify write gadget
                    write_gadget.dst_reg = d_reg
                    write_gadget.Write32(self, 0x20000000, 0x12345678)
                    data = read_gadget.Read32(self, 0x20000000)
                    if data == 0x12345678:
                        logger.info('Write gadget located: 0x{:08X} -> STR {}, [{}]'
                                        .format(address, write_gadget.src_reg, write_gadget.dst_reg))
                        return write_gadget
        return None

    def GetECB(self, read_gadget=None):
        """Dereference the ECBDATAPTR and return the ECB struct as bytearray"""
        if self.isLocked():
            ecb_struct = bytearray()
            for address in range(int(self.chip_info['ECB -> ECBDATAPTR'], 0), int(self.chip_info['ECB -> ECBDATAPTR'], 0) + 48, 4):
                ecb_struct += read_gadget.Read32(self, address).to_bytes(4, byteorder='big')
        else:
            ecb_struct = bytearray(self.dev.read_mem16(int(self.chip_info['ECB -> ECBDATAPTR'], 0), 48))
        return ecb_struct

    def Dumpinfo(self, read_gadget=None):
        """Store chip information with results from FICR/UICR and peripherals"""
        if not self.cortex_m.is_halted():
            self.cortex_m.halt()
        islocked = self.isLocked()
        logger.debug('Reading chip information:')

        rbpconf = read_gadget.Read32(self, nordic.RBPCONF) if islocked else self.dev.get_mem32(nordic.RBPCONF)
        self.chip_info['Protect All'] = 'Enabled' if (rbpconf == 0x00000000) else 'Disabled'
        self.chip_info['Firmware ID'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.FWID) if islocked else self.dev.get_mem32(nordic.FWID))
        self.chip_info['Bootloader address'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.BOOTLOADERADDR) if islocked else self.dev.get_mem32(nordic.BOOTLOADERADDR))
        self.chip_info['Code Page Size'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.CODEPAGESIZE) if islocked else self.dev.get_mem32(nordic.CODEPAGESIZE))
        self.chip_info['Code Memory Size'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.CODESIZE) if islocked else self.dev.get_mem32(nordic.CODESIZE))
        self.chip_info['Total code size (in bytes)'] = '{}'.format(int(self.chip_info['Code Page Size'], 0) * int(self.chip_info['Code Memory Size'], 0))
        self.chip_info['Code Region 0 Length'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.CLENR0) if islocked else self.dev.get_mem32(nordic.CLENR0))
        self.chip_info['Number of RAM Blocks'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.NUMRAMBLOCK) if islocked else self.dev.get_mem32(nordic.NUMRAMBLOCK))
        self.chip_info['Devcie ID 0'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.DEVICEID_0) if islocked else self.dev.get_mem32(nordic.DEVICEID_0))
        self.chip_info['Devcie ID 1'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.DEVICEID_1) if islocked else self.dev.get_mem32(nordic.DEVICEID_1))
        self.chip_info['ECB -> ECBDATAPTR'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.ECBDATAPTR) if islocked else self.dev.get_mem32(nordic.ECBDATAPTR))
        self.chip_info['CCM -> CNFPTR'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.CNFPTR) if islocked else self.dev.get_mem32(nordic.CNFPTR))
        self.chip_info['MPU -> PERR0'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.PERR0) if islocked else self.dev.get_mem32(nordic.PERR0))
        self.chip_info['MPU -> RLENR0'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.RLENR0) if islocked else self.dev.get_mem32(nordic.RLENR0))
        self.chip_info['MPU -> PROTENSET0'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.PROTENSET0) if islocked else self.dev.get_mem32(nordic.PROTENSET0))
        self.chip_info['MPU -> PROTENSET1'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.PROTENSET1) if islocked else self.dev.get_mem32(nordic.PROTENSET1))
        self.chip_info['MPU -> DISABLEINDEBUG'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.DISABLEINDEBUG) if islocked else self.dev.get_mem32(nordic.DISABLEINDEBUG))
        self.chip_info['MPU -> PROTBLOCKSIZE'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.PROTBLOCKSIZE) if islocked else self.dev.get_mem32(nordic.PROTBLOCKSIZE))
        self.chip_info['NVMC -> CONFIG'] = '0x{:08X}'.format(read_gadget.Read32(self, nordic.NVMC_CONFIG) if islocked else self.dev.get_mem32(nordic.NVMC_CONFIG))
        # dump UICR/FICR (Read32 already returns and int32 in big endian)
        for address in (range(nordic.NRF_UICR_BASE, nordic.NRF_UICR_BASE + nordic.UICR_SIZE, 4)):
            self.uicr += (read_gadget.Read32(self, address).to_bytes(4, byteorder='little') if islocked else self.dev.get_mem32(address).to_bytes(4, byteorder='little'))
        for address in (range(nordic.NRF_FICR_BASE, nordic.NRF_FICR_BASE + nordic.FICR_SIZE, 4)):
            self.ficr += (read_gadget.Read32(self, address).to_bytes(4, byteorder='little') if islocked else self.dev.get_mem32(address).to_bytes(4, byteorder='little'))

    def DumpToFile(self, outfile, start_address, end_address, read_gadget=None):
        """Dump memory to specified outfile"""
        fp = open(outfile, 'wb')
        if not self.cortex_m.is_halted():
            self.cortex_m.halt()
        logger.info('Extracting memory from 0x{:08X} to 0x{:08X} ({} bytes)'
                    .format(start_address, end_address, end_address - start_address))
        if self.isLocked():
            for address in tqdm(range(start_address, end_address, 4)):
                fp.write(read_gadget.Read32(self, address).to_bytes(4, byteorder='little'))
        else:
            for address in tqdm(range(start_address, end_address, 4)):
                fp.write(self.dev.get_mem32(address).to_bytes(4, byteorder='little'))
        fp.close()

    def LockTarget(self):
        """Write to UICR-RBPCONF to protect all memory regions"""
        # first enable writing by setting NVMC CONFIG.WEN
        self.dev.set_mem32(nordic.NVMC_CONFIG, nordic.CONFIG_WEN)
        self.dev.set_mem32(nordic.RBPCONF, 0x00000000)
        self.cortex_m.reset_halt()
        data = self.dev.get_mem32(nordic.RBPCONF)
        if data == 0x00000000:
            logger.info('target successfully locked')
        else:
            logger.info('unable to lock target')

    def EraseAll(self):
        """Set the ERASEALL register before unlocking, this does not erase the FICR"""
        if not utils.YesOrNo('dunThis procedure performs a full chip erase of the target\nAre you sure you want to proceed?'):
            logger.info('unlock canceled, exitting')
        else:
            logger.debug('erasing target memory')
            # first enable erasing by setting NVMC CONFIG.EEN
            self.dev.set_mem32(nordic.NVMC_CONFIG, nordic.CONFIG_EEN)
            # erase! (tERASEALL -> 22.3 mS for an nRF51822)
            self.dev.set_mem32(nordic.ERASEALL, 0x00000001)
            sleep(0.2)
            self.dev.set_mem32(nordic.NVMC_CONFIG, nordic.CONFIG_REN)
            self.cortex_m.reset_halt()
            data = self.dev.get_mem32(0x00000000)
            if data == 0xFFFFFFFF:
                return True
            else:
                return False

    def VerifyImage(self, path, start_address, size, read_gadget=None):
        logger.info('verifying {}'.format(path))
        with open(path, "rb") as fp:
            for address in tqdm(range(start_address, start_address + size, 4)):
                if read_gadget:
                    chip_data = read_gadget.Read32(self, address)
                else:
                    chip_data = self.dev.get_mem32(address)
                file_data = int.from_bytes(fp.read(4), byteorder='little')
                if chip_data != file_data:
                    logger.error('{} image failed verifcation at address: 0x{:08X}'.format(path, address))
                    return False
        fp.close()
        logger.debug('{} image passed verifcation'. format(path))
        return True

    def RestoreImage(self, path, write_address):
        """Restore image given by path starting at write_address"""
        logger.info('restoring image {} @ 0x{:08X}'.format(path, write_address))
        self.dev.set_mem32(nordic.NVMC_CONFIG, nordic.CONFIG_WEN)
        image_len = os.path.getsize(path)
        try:
            fp = open(path, 'rb')
        except FileNotFoundError:
            logger.error('file {} not found, specify the -u and -r filename for the UICR and ROM file respectivily'.format(path))

        for address in tqdm(range(write_address, write_address + image_len, 4)):
            data = int.from_bytes(fp.read(4), byteorder='little')
            self.dev.set_mem32(address, data)
        fp.close()

    def Delay(self, delay):
        # reset and resume execution
        logger.info('Counting down {} seconds before performing operation...'.format(delay))
        self.cortex_m.reset()
        self.cortex_m.run()
        for t in tqdm(range(1, delay, 1)):
            sleep(1)

    def ReadAll(self, path, skipverify, read_gadget=None):
        """Read everything to a file, store the directory specified by path"""
        if not os.path.exists(path):
            os.mkdir(path)

        # dump ROM
        start_address = nordic.ROM_START
        end_address = int(self.chip_info['Code Page Size'], 0) * int(self.chip_info['Code Memory Size'], 0)
        file_path = '{}/0x{:08X}_0x{:08X}_ROM.bin'.format(path, start_address, end_address)
        self.DumpToFile(file_path, start_address, end_address, read_gadget)
        if not skipverify:
            if not self.VerifyImage(file_path, start_address, end_address - start_address, read_gadget):
                logger.error('failed to verify image {} -> aborting unlock'.format(file_path))
                exit()

        # FICR
        start_address = nordic.NRF_FICR_BASE
        end_address = nordic.NRF_FICR_BASE + nordic.FICR_SIZE
        file_path = '{}/0x{:08X}_0x{:08X}_FICR.bin'.format(path, start_address, end_address)
        self.DumpToFile(file_path, start_address, end_address, read_gadget)
        if not skipverify:
            if not self.VerifyImage(file_path, start_address, end_address - start_address, read_gadget):
                logger.error('failed to verify image {} -> aborting unlock'.format(file_path))
                exit()

        # UICR
        start_address = nordic.NRF_UICR_BASE
        end_address = nordic.NRF_UICR_BASE + nordic.UICR_SIZE
        file_path = '{}/0x{:08X}_0x{:08X}_UICR.bin'.format(path, start_address, end_address)
        self.DumpToFile(file_path, start_address, end_address, read_gadget)
        if not skipverify:
            if not self.VerifyImage(file_path, start_address, end_address - start_address, read_gadget):
                logger.error('failed to verify image {} -> aborting unlock'.format(file_path))
                exit()

        # PERIPHERALS
        start_address = nordic.NRF_MPU_BASE
        end_address = nordic.NRF_PPI_BASE + 0x1000
        file_path = '{}/0x{:08X}_0x{:08X}_PERIPH.bin'.format(path, start_address, end_address)
        self.DumpToFile(file_path, start_address, end_address, read_gadget)
        if not skipverify:
            if not self.VerifyImage(file_path, start_address, end_address - start_address, read_gadget):
                logger.info('failed to verify image {} -> not a big deal'.format(file_path))
                # this fails to verify sometimes

        # GPIO
        start_address = nordic.NRF_GPIO_BASE
        end_address = nordic.NRF_GPIO_BASE + 0x1000
        file_path = '{}/0x{:08X}_0x{:08X}_GPIO.bin'.format(path, start_address, end_address)
        self.DumpToFile(file_path, start_address, end_address, read_gadget)
        if not skipverify:
            if not self.VerifyImage(file_path, start_address, end_address - start_address, read_gadget):
                logger.error('failed to verify image {} -> aborting unlock'.format(file_path))
                exit()

    def VolatileUnlock(self, read_gadget, path, skipverify):
        """Disable the MPU by storing all the ROM, perform an entire chip erase, and restore the images with the MPU disabled"""
        # start extraction
        if not os.path.exists(path):
            os.mkdir(path)

        # UICR
        start_address = nordic.NRF_UICR_BASE
        end_address = nordic.NRF_UICR_BASE + nordic.UICR_SIZE
        uicr_path = '{}/0x{:08X}_0x{:08X}_UICR.bin'.format(path, start_address, end_address)
        self.DumpToFile(uicr_path, start_address, end_address, read_gadget)
        if not skipverify:
            if not self.VerifyImage(uicr_path, start_address, end_address - start_address, read_gadget):
                logger.error('failed to verify image {} -> aborting unlock'.format(uicr_path))
                exit()
        # dump ROM
        start_address = nordic.ROM_START
        end_address = int(self.chip_info['Code Page Size'], 0) * int(self.chip_info['Code Memory Size'], 0)
        rom_path = '{}/0x{:08X}_0x{:08X}_ROM.bin'.format(path, start_address, end_address)
        self.DumpToFile(rom_path, start_address, end_address, read_gadget)
        if not skipverify:
            if not self.VerifyImage(rom_path, start_address, end_address - start_address, read_gadget):
                logger.error('failed to verify image {} -> aborting unlock'.format(rom_path))
                exit()

        if not self.EraseAll():
            logger.info('erase failed')
            exit()

        utils.UnlockUICRImage(uicr_path)
        self.RestoreImage(uicr_path, nordic.NRF_UICR_BASE)
        self.RestoreImage(rom_path, nordic.ROM_START)

        self.cortex_m.reset_halt()
        is_locked = self.isLocked()

        self.cortex_m.nodebug()

        if not is_locked:
            return True
        else:
            return False
