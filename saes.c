/* 
 saes - AES decrypt cipher from offsets within in files.   
 Copyright (C) 2017  Robert V. <modrobert@gmail.com>

 This program is free software; you can redistribute it and/or
 modify it under the terms of the GNU General Public License
 as published by the Free Software Foundation; either version 2
 of the License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 MA  02110-1301, USA.

 Compile with: gcc -O2 -Wpedantic saes.c aes.c -o saes
*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "aes.h"

#define EXIT_OK 0
#define READ_ERROR 1
#define WRITE_ERROR 2
#define ARG_ERROR 3
#define CIPHER_ERROR 4
#define NCSIZE 16
#define IVSIZE 16

/* prototypes */
int is_hex_string(char *foo);
void lower_string(char *s);
uint64_t bigendian_long(uint64_t x);
unsigned long int check_file_size(FILE *fp);
int test_offset(char *wtf, unsigned long int offset, \
                unsigned long int filesize, int bufsize);

/* macros and globals */
int pout = 1; /* quiet flag */
#define PRINT(...) if(pout){printf(__VA_ARGS__);}
const int etest = 1;
#define is_bigendian() ( (*(char*)&etest) == 0 )

int main(int argc, char *argv[])
{
 const char *PROGTITLE = "saes v0.96 by modrobert in 2017\n";
 FILE *ivfile, *keyfile, *source, *target; 
 int loop, opt;
 size_t nc_off = 0;
 int bytes_read;
 int bytes_write;
 unsigned int keysize = 16;
 unsigned int keysizebits = keysize * 8;
 int buffersize = 16;
 size_t aeslength = (size_t)buffersize;
 unsigned long int cipheroffset, ivoffset, keyoffset;
 unsigned long int cipherfilesize, ivfilesize, keyfilesize;
 unsigned long int d_bytes;
 unsigned char iv[IVSIZE];
 unsigned char nc[NCSIZE];
 unsigned char dm[NCSIZE];
 uint64_t nctemp;
 uint64_t ncounter = 0;
 char *pnc = (char *)&ncounter;
 aes_context ctx;
 int aes_result;
 int aflag = 0; /* AES key size */
 int bflag = 0; /* block cipher mode */
 int cflag = 0; /* cipher input file */
 int hflag = 0; /* help flag */
 int iflag = 0; /* IV file */
 int kflag = 0; /* key file */
 int lflag = 0; /* buffer size */
 int oflag = 0; /* output file */
 int qflag = 0; /* quit flag */
 int sflag = 0; /* IV offset */
 int tflag = 0; /* key offset */
 int uflag = 0; /* cipher offset */ 
 int vflag = 0; /* nonce counter */ 
 char *avalue = "a", *bvalue = "b", *cvalue = "c", *ivalue = "i", *kvalue = "k";
 char *lvalue = "l", *ovalue = "o", *svalue = "s", *tvalue = "t", *uvalue ="u";
 char *vvalue = "v";

 /* clear buffers */
 memset(iv, 0, sizeof iv);
 memset(nc, 0, sizeof nc);
 memset(dm, 0, sizeof dm);
 
 opterr = 1; /* turn on getopt '?' error handling */

 /* handle arguments */
 while ((opt = getopt (argc, argv, "a:b:c:hi:k:l:o:qs:t:u:v:")) != -1)
 {
  switch (opt)
  {
   case 'a':
    aflag = 1;
    avalue = optarg;
    keysizebits = atoi(avalue);
    keysize = keysizebits >> 3; /* integer division by 8 ;) */
    break;
   case 'b':
    bflag = 1;
    bvalue = optarg;
    lower_string(bvalue);
    break;
   case 'c':
    cflag = 1;
    cvalue = optarg;
    break;
   case 'h':
    hflag = 1;
    break;
   case 'i':
    iflag = 1;
    ivalue = optarg;
    break;
   case 'k':
    kflag = 1;
    kvalue = optarg;
    break;
   case 'l':
    lflag = 1;
    lvalue = optarg;
    if (is_hex_string(lvalue))
     buffersize = strtol(lvalue, NULL, 16);
    else
     buffersize = atol(lvalue);
    aeslength = (size_t)buffersize;
    break;
   case 'o':
    oflag = 1;
    ovalue = optarg;
    break;
   case 'q':
    qflag = 1;
    pout = 0;
    break;
   case 's':
    sflag = 1;
    svalue = optarg;
    if (is_hex_string(svalue))
     ivoffset = strtol(svalue, NULL, 16);
    else
     ivoffset = atol(svalue);
    break;
   case 't':
    tflag = 1;
    tvalue = optarg;
    if (is_hex_string(tvalue))
     keyoffset = strtol(tvalue, NULL, 16);
    else
     keyoffset = atol(tvalue);
    break;
   case 'u':
    uflag = 1;
    uvalue = optarg;
    if (is_hex_string(uvalue))
     cipheroffset = strtol(uvalue, NULL, 16);
    else
     cipheroffset = atol(uvalue);
    break;
   case 'v':
    vflag = 1;
    vvalue = optarg;
    if (is_hex_string(vvalue))
     nctemp = strtol(vvalue, NULL, 16);
    else
     nctemp = atol(vvalue);
    ncounter = bigendian_long(nctemp); /* convert to big endian */
    memcpy(nc + 8, pnc, 8); /* copy big endian CTR counter */
    break;
   default: /* '?' */ 
    fprintf(stderr, "Usage: %s -abckot [-ilhqsuv]\n", argv[0]);
    fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
    exit(ARG_ERROR);
  }
 }

 PRINT("%s", PROGTITLE);

 if (argc == 1)
 {
  fprintf(stderr, "Usage: %s -abckot [-ilhqsuv]\n", argv[0]);
  fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
  exit(ARG_ERROR);
 }

 if (hflag)
 {
  PRINT("Function: AES decrypt cipher from offsets within files.\n");
  PRINT("Syntax  : saes -a <key size bits> -b <block mode> -c <cipher file> "
        "[-h]\n"
        "          [-i <iv file>] -k <key file> [-l <cbc/ctr length *>] "
        "-o <output file>\n" 
        "          [-q] [-s <iv offset *>] -t <key offset *> "
        "[-u <cipher offset *>]\n"
        "          [-v <ctr counter *>]\n");
  PRINT("Options : -a can be 128, 192 or 256 bits in length\n");
  PRINT("          -b can be 'ECB', 'CBC' and 'CTR'\n");
  PRINT("          -l needs to be a multiple of 16 bytes for ECB, not CTR\n");
  PRINT("          -q quiet flag, only errors reported\n");
  PRINT("          -v ctr counter for AES-CTR, prog converts to big-endian "
        "as needed\n");
  PRINT("          *) can be in integer decmial or hex (0x) format\n");
  PRINT("Result  : 0 = ok, 1 = read error, 2 = write error, 3 = arg error,\n"
        "          4 = cipher error.\n");
  exit(EXIT_OK);
 }

 for (loop = optind; loop < argc; loop++)
  PRINT("Ignoring non-option argument: %s\n", argv[loop]);

 /* general sanity checks */

 /* only allow 128, 192 or 256 bits key length supported by AES */
 if (keysizebits != 128 && keysizebits != 192 && keysizebits != 256)
 {
  fprintf(stderr, "Invalid key length of %d bits (needs to be 128, 192 or 256)"
                   ".\n", keysizebits);
  fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
  exit(ARG_ERROR);
 }

 /* make sure CBC length option is a multiple of 16 */
 
 if (strcmp(bvalue, "cbc") == 0 && aeslength % 16 != 0)
 {
  fprintf(stderr, "CBC length needs to be a multiple of 16 bytes.\n");
  fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
  exit(ARG_ERROR);
 }

 /* check given filenames for dupes and bad combos */
 if (strcmp(cvalue, ivalue) == 0 || strcmp(cvalue, kvalue) == 0)
 {
  fprintf(stderr, "Cipher file given more than once, copy as "
          "needed to unique files.\n");
  fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
  exit(ARG_ERROR);
 }
 if (strcmp(ovalue, cvalue) == 0 || strcmp(ovalue, ivalue) == 0 || \
     strcmp(ovalue, kvalue) == 0)
 {
  fprintf(stderr, "Output file also given as input, check arguments!\n");
  fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
  exit(ARG_ERROR);
 }

 /* check options depending on block mode */
 if (strcmp(bvalue, "ecb") == 0)
 {
  if ((aflag + bflag + cflag + kflag + oflag + tflag) != 6 \
       || (iflag + sflag) != 0)
  {
   fprintf(stderr, "Missing or wrong options for ECB block mode.\n");
   fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
   exit(ARG_ERROR);
  }
  PRINT("AES-%s-ECB mode enabled.\n", avalue);
  if (lflag) PRINT("Warning; -l option is ignored for ECB, length is fixed "
                   "at 16 bytes.\n");
  buffersize = 16;
 } 
 else if (strcmp(bvalue, "cbc") == 0)
 {
  if ((aflag + bflag + cflag + iflag + kflag + lflag + oflag + sflag + tflag) \
      != 9)
  {
   fprintf(stderr, "Missing options for CBC block mode.\n");
   fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
   exit(ARG_ERROR);
  }
  PRINT("AES-%s-CBC mode enabled with length %d.\n", avalue, buffersize);
 }
 else if (strcmp(bvalue, "ctr") == 0)
 {
  if (vflag)
  {
   if ((aflag + bflag + cflag + kflag + lflag + oflag + tflag + vflag) != 8 \
        || (iflag + sflag) != 0)
   {
    fprintf(stderr, "Missing or wrong options for CTR block mode with -v "
            "counter .\n");
    fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
    exit(ARG_ERROR);
   }
   PRINT("AES-%s-CTR mode enabled with counter %s from -v option.\n", \
         avalue, vvalue);
  }
  else if (iflag)
  {
   if ((aflag + bflag + cflag + iflag + kflag + lflag + oflag + sflag + tflag)\
        != 9)
   {
    fprintf(stderr, "Missing or wrong options for CTR block mode using IV file"
            ".\n");
    fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
    exit(ARG_ERROR);
   }
   PRINT("AES-%s-CTR mode enabled with counter and nonce from IV file.\n", \
         avalue);
  }
 }
 else
 {
  fprintf(stderr, "Unsupported cipher block mode.\n");
  fprintf(stderr, "Try '%s -h' for more information.\n", argv[0]);
  exit(ARG_ERROR);
 }

 /* declaring variable buffers */
 unsigned char key[keysize];
 unsigned char buffera[buffersize];
 unsigned char bufferb[buffersize];

 /* clear variable buffers */
 memset(key, 0, sizeof key);
 memset(buffera, 0, sizeof buffera);
 memset(bufferb, 0, sizeof bufferb);

 /* open the files */ 
 if (iflag)
 {
  if ((ivfile = fopen(ivalue, "rb")) == NULL)
  {
   fprintf(stderr, "IV file not found: %s\n", ivalue);
   exit(READ_ERROR);
  }
 }

 if ((keyfile = fopen(kvalue, "rb")) == NULL)
 {
  fprintf(stderr, "Key file not found: %s\n", kvalue);
  if (iflag) fclose(ivfile);
  exit(READ_ERROR);
 } 
 else if ((source = fopen(cvalue, "rb")) == NULL)
 {
  fprintf(stderr, "Cipher file not found: %s\n", cvalue);
  
  if (iflag) fclose(ivfile); 
  fclose(keyfile);
  exit(READ_ERROR);
 } 
 else if ((target = fopen(ovalue, "wb")) == NULL)
 {
  fprintf(stderr, "Error while opening output file: %s\n", ovalue);
  if (iflag) fclose(ivfile); 
  fclose(keyfile); fclose(source);
  exit(WRITE_ERROR);
 }

 if (iflag)
 { 
  /* sizing the IV file */
  ivfilesize = check_file_size(ivfile);

  /* seek to IV offset */
  if (test_offset("IV", ivoffset, ivfilesize, IVSIZE))
  {
   fseek(ivfile, ivoffset, SEEK_SET);
  }
  else
  {
   fclose(ivfile); fclose(keyfile); fclose(source); fclose(target);
   remove(ovalue);
   exit(READ_ERROR);
  }
 }

 if (uflag)
 { 
  /* sizing the cipher file aka source */
  cipherfilesize = check_file_size(source);

  /* seek to cipher offset */
  if (test_offset("cipher", cipheroffset, cipherfilesize, keysize))
  {
   fseek(source, cipheroffset, SEEK_SET);
  }
  else
  {
   if (iflag) fclose(ivfile);
   fclose(keyfile); fclose(source); fclose(target);
   remove(ovalue);
   exit(READ_ERROR);
  }
 }

 /* sizing the key file */
 keyfilesize = check_file_size(keyfile);
 
 /* seek to key offset */
 if (test_offset("key", keyoffset, keyfilesize, keysize))
 {
  fseek(keyfile, keyoffset, SEEK_SET);
 }
 else
 {
  if(iflag) fclose(ivfile); 
  fclose(keyfile); fclose(source); fclose(target);
  remove(ovalue);
  exit(READ_ERROR);
 }

/* reading IV */
 if (iflag)
 {
  if ((bytes_read = fread(iv, 1, IVSIZE, ivfile)) <= 0)
  {
   fprintf(stderr, "Error while reading IV file: %s\n", ivalue);
   fclose(ivfile); fclose(keyfile); fclose(source); fclose(target);
   exit(READ_ERROR);
  } 
  else
  {
   if (strcmp(bvalue, "ctr") == 0) memcpy(nc, iv, IVSIZE);
   PRINT("Read %d bytes of IV from %s at offset %lu (0x%02lx).\n", \
          bytes_read, ivalue, ivoffset, ivoffset);
   fclose(ivfile);
  }
 }
 
 /* reading key */
 if ((bytes_read = fread(key, 1, keysize, keyfile)) <= 0)
 {
  fprintf(stderr, "Error while reading key file: %s\n", kvalue);
  fclose(ivfile); fclose(keyfile); fclose(source); fclose(target);
  exit(READ_ERROR);
 } 
 else
 {
  PRINT("Read %d bytes of key from %s at offset %lu (0x%02lx).\n", \
         bytes_read, kvalue, keyoffset, keyoffset);
  fclose(keyfile);
 }
 
 d_bytes = 0;
 bytes_read = buffersize;
 
 /* init AES and set key */
 if (strcmp(bvalue, "ctr") == 0)
 {
  /* AES-CTR requires aes_setkey_enc for decryption, check aes.h if in doubt */
  if (aes_setkey_enc(&ctx, key, keysizebits) != 0)
  {
   fprintf(stderr, "AES-%s-%s error while setting key and init.\n", \
           avalue, bvalue);
   fclose(source); fclose(target);
   exit(CIPHER_ERROR);
  }
 }
 else
 {
  if (aes_setkey_dec(&ctx, key, keysizebits) != 0)
  {
   fprintf(stderr, "AES-%s-%s error while setting key and init.\n", \
           avalue, bvalue);
   fclose(source); fclose(target);
   exit(CIPHER_ERROR);
  }
 } 

 /* start processing files */ 
 PRINT("Decrypting: %s\nWriting   : %s\n", cvalue, ovalue);
 while (!feof(source))
 {
  if ((bytes_read = fread(buffera, 1, buffersize, source)) <= 0)
  {
   if (feof(source)) break;
   fprintf(stderr, "\n");
   fprintf(stderr, "Error while reading cipher file: %s\n", cvalue);
   fclose(source); fclose(target);
   exit(READ_ERROR);
  }
  bytes_write = bytes_read;
  if (strcmp(bvalue, "ecb") == 0)
  {
   aes_result = aes_crypt_ecb(&ctx, AES_DECRYPT, buffera, \
   bufferb);
   if (aes_result != 0)
   {
    fprintf(stderr, "AES-%s-ECB error %d while decrypting.\n", \
            avalue, aes_result);
    fclose(source); fclose(target);
    exit(CIPHER_ERROR);
   }
  }
  else if (strcmp(bvalue, "cbc") == 0)
  {
   aes_result = aes_crypt_cbc(&ctx, AES_DECRYPT, aeslength, iv, buffera, \
                              bufferb);
   if (aes_result != 0)
   {
    fprintf(stderr, "AES-%s-CBC error %d while decrypting.\n", \
            avalue, aes_result);
    fclose(source); fclose(target);
    exit(CIPHER_ERROR);
   }
  }
  else if (strcmp(bvalue, "ctr") == 0)
  {
   aes_result = aes_crypt_ctr(&ctx, aeslength, &nc_off, nc, dm, buffera, \
                              bufferb);
   if (aes_result != 0)
   {
    fprintf(stderr, "AES-%s-CTR error %d while decrypting.\n", \
            avalue, aes_result);
    fclose(source); fclose(target);
    exit(CIPHER_ERROR);
   }
  }
  d_bytes = d_bytes + bytes_write;
  PRINT("\rBytecount : %lu (0x%02lx)", d_bytes, d_bytes);
  if (fwrite(bufferb, 1, bytes_write, target) != bytes_write)
  {
   fprintf(stderr, "\n");
   fprintf(stderr, "Error while writing output file: %s\n", ovalue);
   fclose(source); fclose(target);
   exit(WRITE_ERROR);
  }
 }
 fclose(source); fclose(target);
 
 PRINT("\n");
 return (EXIT_OK);
} /* main */


/* functions */

int is_hex_string(char *foo)
{
 if (strncmp(foo, "0x", 2) == 0)
  return 1;
 else
  return 0;
}

void lower_string(char *s)
{
 int c = 0;
 while (s[c] != '\0')
 {
  if (s[c] >= 'A' && s[c] <= 'Z')
  {
   s[c] = s[c] + 32;
  }
  c++;
 }
}

uint64_t bigendian_long(uint64_t x)
{
 uint64_t j;
 char *c = (char *)&j;
 uint64_t i;
 char *p = (char *)&i;
 j = x;

 if (is_bigendian())
 {
  return x;
 }
 else
 {
  p[0] = c[7];
  p[1] = c[6];
  p[2] = c[5];
  p[3] = c[4];
  p[4] = c[3];
  p[5] = c[2];
  p[6] = c[1];
  p[7] = c[0];
 }
 return i;
}

unsigned long int check_file_size(FILE *fp)
{
 unsigned long int fsize;
 fseek(fp, 0L, SEEK_END);
 fsize = ftell(fp);
 fseek(fp, 0L, SEEK_SET);
 return fsize;
}

int test_offset(char *wtf, unsigned long int offset, \
                unsigned long int filesize, int bufsize)
{
 if (offset >= filesize)
 {
  fprintf(stderr, "Given offset [%lu] is bigger than size [%lu] of %s file.\n"\
          , offset, filesize, wtf);
  return 0;
 }
 else
 {
  if ((offset + bufsize) > filesize)
  {
   PRINT("Warning; offset gives %s length less "
         "than %d bytes (%d bits).\n", wtf, bufsize, bufsize * 8);
  }
  return 1;
 }
}

