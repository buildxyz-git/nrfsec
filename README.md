# nrfsec 

nrfsec is security research tool used for unlocking and reading memory on nrf51 series SoCs from Nordic Semiconductor. 

  - Read all target memory, bypassing the Memory Protection Unit (MPU) settings with integrated read gadget searching.
  - Automated unlock feature: read all program and UICR memory, erase all memory, patch UICR image, reflash target into unlocked state.
  - Boot delay command flag for interacting with target prior to performing memory read, allowing for RAM dumps.
  - All firmware images are saved for importing into your favorite disassembler.

### Installation
nrfsec is built on the [pyswd library](https://github.com/cortexm/pyswd/) and currently only works with the [ST-Link](https://www.adafruit.com/product/2548) debugging interface.

nrfsec requires python 3.7+ to run and can be installed with pip:

```sh
pip3 install nrfsec
```

### Info
A quick info check will ensure that nrfsec is able to communicate with both the debugger and the target. The output for the info will also specify if the target is currently locked with some additional interesting target information. 
```sh
nrfsec info
```
![Get chip information](https://raw.githubusercontent.com/buildxyz-git/nrfsec/master/images/nrfsec_info.gif)
Specifying the verbose flag here with dump the previously mentioned information plus the full contents of both the UICR and FICR. All the information displayed here can be found by interpreting registers contained within the UICR and FICR.


### Read
nrfsec will automatically find a useable read gadget and dump all memory on a locked target. nrfsec will store all the extracted images in /fw of the current working directory. The below example can be used to automatically read all memory regions by parsing memory specifications located in the FICR.
```sh
nrfsec read -a
```
![Read all memory](https://raw.githubusercontent.com/buildxyz-git/nrfsec/master/images/nrfsec_readall.gif)

Read specified memory regions with an optional delay before beginning memory extraction. Great for interacting with the target though any associated mobile applications in order to populate RAM and intialize peripherals.
```sh
nrfsec read -s 0x1000 -e 0x2000 -d 8 -o outfile.bin 
```
![Read Delay](https://raw.githubusercontent.com/buildxyz-git/nrfsec/master/images/nrfsec_read_delay.gif)


### Lock
Issuing the lock sub-command will the target again. This was useful in developing nrfsec but can also be used if you simply want to lock your target if it is not already locked.
```sh
nrfsec lock
```
![Lock target](https://raw.githubusercontent.com/buildxyz-git/nrfsec/master/images/nrfsec_locktarget.gif)


### Unlock
The unlock sub command will perform the following steps:
1.	Read all memory regions (most importantly, ROM and UICR) and save the images.
2.	Perform a full target erase, this will enable writing to the UICR again
3.	Patch the UICR image extracted during step 1 to disable read back protection
4.	Re-flash the ROM and patched UICR back to the target

```sh
nrfsec unlock
```
![Unlock target](https://raw.githubusercontent.com/buildxyz-git/nrfsec/master/images/nrfsec_unlock.gif)

Debug sessions are now possible.


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

