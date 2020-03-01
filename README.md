# nrfsec 

nrfsec is security research tool used for unlocking and reading memory on nrf51 series SoCs from Nordic Semiconductor. 

  - Read all target memory, bypassing the Memory Protection Unit (MPU) settings with integrated read gadget searching
  - Automated unlock feature: read all program and UICR memory, erase all memory, patch UICR image, reflash target into unlocked state
  - boot delay command flag for interacting with target prior to performing memory read, allow for RAM dumps
  - All firmware images are saved for importing into your favorite disassembler 

### Installation

nrfsec is built on the [pyswd library](https://github.com/cortexm/pyswd/) and currently only works with the [ST-Link](https://www.adafruit.com/product/2548) debugging interface.

nrfsec requires python 3.7+ to run and can be installed with pip

```sh
pip3 install nrfsec
```

### Usage
```sh
✗ nrfsec -h
usage: nrfsec <command> [<args>]

perform security related tasks on nRF51 targets through SWD interface

optional arguments:
  -h, --help            show this help message and exit
  -f FREQUENCY, --frequency FREQUENCY
                        frequency to run the SWD interface (default 4 MHz)
  -v, --verbose         increase output verobsity

supported subcommands:
  {info,erase,restore,read,unlock,lock}
    info                display chip information
    erase               perform a complete erase
    restore             restore specific images to an unlocked chip
    read                read memory contents to outfile
    unlock              unlock the device if locked
    lock                lock the device if unlocked
```

### Todos

 - Test on moar targets

License
----

GNU GPLv3 

