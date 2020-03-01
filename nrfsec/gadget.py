# -*- coding: utf-8 -*-


class Gadget:
    """Class to hold the gadget values"""
    def __init__(self, address=None, src_reg=None, dst_reg=None):
        self.address = address
        self.dst_reg = dst_reg
        self.src_reg = src_reg


class ReadGadget(Gadget):
    """Subclass to hold read gadget values"""
    def Read32(self, dev, address):
        """Use read gadget to dump a word (4 bytes) from address"""
        dev.cortex_m.set_reg('PC', self.address)
        dev.cortex_m.set_reg(self.src_reg, address)
        dev.cortex_m.step()
        data = dev.cortex_m.get_reg(self.dst_reg)
        return data


class WriteGadget(Gadget):
    """Subclass to hold write gadget values"""
    def Write32(self, dev, address, value):
        """Use write gadget to store a word (4 bytes) @ address"""
        dev.cortex_m.set_reg('PC', self.address)
        dev.cortex_m.set_reg(self.dst_reg, address)
        dev.cortex_m.set_reg(self.src_reg, value)
        dev.cortex_m.step()