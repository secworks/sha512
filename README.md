sha512
======

Verilog implementation of the SHA-512 hash function. This implementation
complies with the functionality in NIST FIPS 180-4. The supports the
SHA-512 variants SHA-512/224, SHA-512/256, SHA-384 and SHA-512.


## Implementation details ##
The core uses a sliding window with 16 64-bit registers for the W
memory. The top level wrapper contains flag control registers for init
and next that automatically resets. This means that the flags must be
set for every block to be processed.


## Status ##
***(2014-04-05)***

RTL for the core and top is completed Testbenches for core and top
completed. All single block and dual block test cases works. Results
after building the complete design for Altera Cyclone V GX:

- 2919 ALMs
- 3609 Registers
- 77 MHz max clock frequency


***(2014-03-24)***

Core works for the SHA-512 mode case. Added top level wrapper and built
the design for Altera Cyclone V GX:

- 2923 ALMs
- 3609 Registers
- 80 MHz max clock frequency



***(2014-02-23)***

Initial version. Based on the SHA-256 core. Nothing really to see yet.
