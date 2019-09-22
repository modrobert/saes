# saes

## Decrypt AES cipher using keys and data from offsets within files.

### Copyright (C) 2017  Robert V. &lt;modrobert@gmail.com&gt;
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
Syntax  : saes -a &lt;key size bits&gt; -b &lt;block mode&gt; -c &lt;cipher file&gt; [-h]
          [-i &lt;iv file&gt;] -k &lt;key file&gt; [-l &lt;cbc/ctr length *&gt;] -o &lt;output file&gt;
          [-q] [-s &lt;iv offset *&gt;] -t &lt;key offset *&gt; [-u &lt;cipher offset *&gt;]
          [-v &lt;ctr counter *&gt;]
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

Use included Makefile or compile with:  
gcc -O2 -Wpedantic saes.c aes.c -o saes

