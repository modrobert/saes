# saes

## Decrypt AES cipher using keys and data from offsets within files.

### Copyright (C) 2017  Robert V. <modrobert@gmail.com>
### Software licensed under GPLv2.

---

### Description

Program abbreviated 'saes' as in "sliding AES".

The idea is to use a scripting language (eg. Python, Perl, Bash) to call this
program which will decrypt a file at given offset using a key in another file
at a given offset, and finally initialization vector (IV) from a third file at
given offset depending on decryption method used.

This is useful when you want to perform "sliding window" and similar methods to
attempt decryption of data incrementally while also sliding through a suspect
file dump with potential key, and file containing IV.

The main reason I wrote this program in C was to get performance when testing
many input files while generating several hundred thousand potentially
decrypted file dumps for later analysis.

---

### Usage

<pre>
$ saes -h
saes v0.96 by modrobert in 2017
Function: AES decrypt cipher from offsets within files.
Syntax  : saes -a <key size bits> -b <block mode> -c <cipher file> [-h]
          [-i <iv file>] -k <key file> [-l <cbc/ctr length *>] -o <output file>
          [-q] [-s <iv offset *>] -t <key offset *> [-u <cipher offset *>]
          [-v <ctr counter *>]
Options : -a can be 128, 192 or 256 bits in length
          -b can be 'ECB', 'CBC' and 'CTR'
          -l needs to be a multiple of 16 bytes for ECB, not CTR
          -q quiet flag, only errors reported
          -v ctr counter for AES-CTR, prog converts to big-endian as needed
          *) can be in integer decmial or hex (0x) format
Result  : 0 = ok, 1 = read error, 2 = write error, 3 = arg error,
          4 = cipher error.
</pre>

---

### Build

Compile with:  
gcc -O2 -Wpedantic saes.c aes.c -o saes

