sha512
======
Verilog implementation of the SHA-512 hash function. This implementation
complies with the functionality in NIST FIPS 180-4. The supports the
SHA-512 variants SHA-512/224, SHA-512/256, SHA-384 and SHA-512.


## Status ##
The core is completed and is considered mature. The core has been used
in more than one FPGA design.


## Implementation details ##
The core uses a sliding window with 16 64-bit registers for the W
memory. The top level wrapper contains flag control registers for init
and next that automatically resets. This means that the flags must be
set for every block to be processed.


## FPGA-results ##

### Xilinx FPGAs ###
Implementation results using ISE 14.7.

***Artix-7***
- xc7a200t-3fbg484
- 4869 Slice LUTs
- 1575 Slices
- 3918 regs
- 96 MHz


***Spartan-6***
- xc6slx45-3csg324
- 4333 LUTs
- 1300 Slices
- 3853 regs
- 57 MHz


### Altera FPGAs ###

***Altera Cyclone V GX***
- 2923 ALMs
- 3609 Registers
- 80 MHz max clock frequency
