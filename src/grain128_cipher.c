///////////////////////////////////////////////////////////////////////////////
// grain128_cipher.c: C99 implementation + unit-test of Pre-Output Generator //
// Version 1.0.0 (30-11-22), see <http://github.com/johgrolux/> for updates. //
// License: GPLv3 (see LICENSE file), other licenses available upon request. //
// ------------------------------------------------------------------------- //
// This source code is free software: you can redistribute it and/or modify  //
// it under the terms of the GNU General Public License as published by the  //
// Free Software Foundation, either version 3 of the License, or (at your    //
// option) any later version. This source code is distributed in the hope    //
// that it will be useful, but WITHOUT ANY WARRANTY; without even the        //
// implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  //
// See the GNU General Public License for more details. You should have      //
// received a copy of the GNU General Public License along with this source  //
// code. If not, see <http://www.gnu.org/licenses/>.                         //
///////////////////////////////////////////////////////////////////////////////


#include <stdio.h>
#include <string.h>
#include <stdint.h>


typedef unsigned char UChar;
typedef unsigned long long int ULLInt;


typedef struct {
  uint32_t lfsr[4];  // LFSR
  uint32_t nfsr[4];  // NFSR
  uint64_t A, R, S;  // Accumulator, Register, and next Auth-keystream
  uint32_t z;        // Message-keystream
} grain_ctx;


#if (defined(__AVR) || defined(__AVR__))
extern uint16_t grain_keystr16_avr(grain_ctx *grain);
#define grain_keystr16_asm(grain) grain_keystr16_avr((grain))
#define GRAIN_ASSEMBLER
#endif

#if (defined(__MSP430__) || defined(__ICC430__))
extern uint16_t grain_keystr16_msp(grain_ctx *grain);
#define grain_keystr16_asm(grain) grain_keystr16_msp((grain))
#define GRAIN_ASSEMBLER
#endif


#define N64(byte) (*(uint64_t *) (((uint8_t *) grain->nfsr) + (byte)))
#define L64(byte) (*(uint64_t *) (((uint8_t *) grain->lfsr) + (byte)))
#define N32(byte) (*(uint32_t *) (((uint8_t *) grain->nfsr) + (byte)))
#define L32(byte) (*(uint32_t *) (((uint8_t *) grain->lfsr) + (byte)))
#define N16(byte) (*(uint16_t *) (((uint8_t *) grain->nfsr) + (byte)))
#define L16(byte) (*(uint16_t *) (((uint8_t *) grain->lfsr) + (byte)))


// Shift the LFSR or NFSR to the right by n bits.
 
static inline void shift_reg128(void *reg, int n)
{
  uint32_t *reg32 = (uint32_t *) reg;
  
  reg32[0] = (reg32[0] >> n) | (reg32[1] << (32 - n));
  reg32[1] = (reg32[1] >> n) | (reg32[2] << (32 - n));
  reg32[2] = (reg32[2] >> n) | (reg32[3] << (32 - n));
  reg32[3] = (reg32[3] >> n);
}


// Print the content of the LFSR and NFSR in Hex format.

static void print_grain(const grain_ctx *grain)
{
  UChar buffer[84], byte;
  int i, j, k = 0;
  
  // printf("LFSR:");
  // for (i = 0; i < 4; i++) {
  //   printf(" %08lx", grain->lfsr[i]);
  // }
  // printf("\n");
  // printf("NFSR:");
  // for (i = 0; i < 4; i++) {
  //   printf(" %08lx", grain->nfsr[i]);
  // }
  // printf("\n");
  
  memcpy(&buffer[k], "LFSR:", 5);
  k += 5;
  for (i = 0; i < 4; i++) {
    buffer[k++] = ' ';
    for (j = 7; j >= 0; j--) {
      byte = (grain->lfsr[i] >> 4 * j) & 0xf;
      // replace 87 by 55 to get uppercase letters
      buffer[k++] = byte + ((byte < 10) ? 48 : 87);
    }
  }
  buffer[k++] = '\n';
  
  memcpy(&buffer[k], "NFSR:", 5);
  k += 5;
  for (i = 0; i < 4; i++) {
    buffer[k++] = ' ';
    for (j = 7; j >= 0; j--) {
      byte = (grain->nfsr[i] >> 4 * j) & 0xf;
      // replace 87 by 55 to get uppercase letters
      buffer[k++] = byte + ((byte < 10) ? 48 : 87);
    }
  }
  buffer[k++] = '\0';
  
  printf("%s\n", buffer);
}


///////////////////////////////////////////////////////////////////////////////
#if (INTPTR_MAX > 2147483647LL) ///// IMPLEMENTATION FOR 64-BIT PLATFORMS /////
///////////////////////////////////////////////////////////////////////////////


// The 1st version of the Pre-Output Generator is based on the source code in
// `grain128aead-v2_opt.cpp` of the `x64` implementation from the designers.
// This version is only suitable for microcontrollers that can handle unaligned
// memory accesses, such as ARMv7-M (e.g. Cortex-M3 and M4), but not MSP430.
// The function shifts both the LSFR and NFSR 32 bits and returns 32 pre-output
// bits.

uint32_t grain_keystr32_V1(grain_ctx *grain)
{
  uint32_t nn4, y;
  
  // g-function (update of NSFR)
  
  uint64_t ln0 = L64(0), nn0 = N64(0), nn1 = N64(4), nn2 = N64(8);
  uint64_t nn2_p16 = N64(6), nn0_2 = nn0 >> 2, nn0_1 = nn0 >> 1;
  
  nn4  = (uint32_t) (ln0 ^ nn0 ^ N64(12) ^ (((nn0 & nn1) ^ nn2) >> 27));
  nn4 ^= (uint32_t) (((nn0 & nn2) >> 3) ^ ((nn0 & nn0_2) >> 11));
  nn4 ^= (uint32_t) (((nn0 & nn0_1) ^ ((nn1 >> 12) & nn2_p16)) >> 17);
  nn4 ^= (uint32_t) ((N64(5) & N64(6)) ^ ((nn2_p16 & nn2) >> 20));
  nn4 ^= (uint32_t) ((nn0_2 ^ nn1 ^ ((nn0 & (nn0 << 2)) & nn0_1)) >> 24);
  nn4 ^= (uint32_t) (N64(11) & (nn2 >> 28) & (nn2 >> 29) & (nn2 >> 31));
  nn4 ^= (uint32_t) (((nn2 & N64(9)) >> 6) & (nn2 >> 18));
  
  N64(0) = nn1;
  N32(8) = N32(12);
  N32(12) = nn4;
  
  // f-function (update of LSFR)
  
  uint64_t ln2 = L64(8), ln1 = L64(4);
  uint64_t ln2_17 = ln2 >> 17, ln0_7 = ln0 >> 7;
  
  L64(0) = ln1;
  L32(8) = L32(12);
  L32(12) ^= ln0 ^ ((ln1 ^ ln2) >> 6) ^ ln0_7 ^ ln2_17;
  
  // h-function (pre-output bits)
  
  uint64_t nn2_21 = nn2 >> 21;
  
  y  = (uint32_t) (nn2 ^ nn0_2 ^ (nn1 >> 4));
  y ^= (uint32_t) (((nn2 ^ nn2_p16) >> 25) ^ ((ln1 >> 28) & (ln2 >> 15)));
  y ^= (uint32_t) ((ln2_17 ^ (nn0 & (ln0 << 4))) >> 12);
  y ^= (uint32_t) (((ln0 & ln0_7) ^ nn1 ^ nn0_2) >> 13);
  y ^= (uint32_t) (((ln1 & nn2_21) ^ (nn0_2 & nn2_21 & (ln2 >> 20))) >> 10);
  
  return y;
}


// The 2nd version of the Pre-Output Generator is similar to the 1st version
// but ensures that all memory accesses (e.g. loads and stores of words from
// are LFSR and NFSR) are properly aligned. The function shifts both the LSFR
// and the NFSR 32 bits and returns 32 pre-output bits.

uint32_t grain_keystr32_V2(grain_ctx *grain)
{
  uint32_t *lptr = grain->lfsr;
  uint32_t *nptr = grain->nfsr;
  uint32_t l4, n4, y;
  int i;
  
  uint64_t l0 = (((uint64_t) lptr[1]) << 32) | lptr[0];
  uint64_t l1 = (((uint64_t) lptr[2]) << 32) | lptr[1];
  uint64_t l2 = (((uint64_t) lptr[3]) << 32) | lptr[2];
  uint64_t l3 = (((uint64_t) lptr[3]));
  
  uint64_t n0 = (((uint64_t) nptr[1]) << 32) | nptr[0];
  uint64_t n1 = (((uint64_t) nptr[2]) << 32) | nptr[1];
  uint64_t n2 = (((uint64_t) nptr[3]) << 32) | nptr[2];
  uint64_t n3 = (((uint64_t) nptr[3]));
  
  // g-function (update of NSFR)
  // shift distances: 1 3 4 6 8 11 13 14 16 17 18 20 22 24 25 26 27 28 29 31
  
  n4  = (uint32_t) (l0 ^ n0 ^ (n0 >> 26));                  // s0 b0 b26
  n4 ^= (uint32_t) ((n1 >> 24) ^ (n2 >> 27) ^ n3);          // b56 b91 b96
  n4 ^= (uint32_t) ((n0 & n2) >>  3);                       // b3b67
  n4 ^= (uint32_t) ((n0 >> 11) & (n0 >> 13));               // b11b13
  n4 ^= (uint32_t) ((n0 >> 17) & (n0 >> 18));               // b17b18
  n4 ^= (uint32_t) ((n0 & n1) >> 27);                       // b27b59
  n4 ^= (uint32_t) ((n1 >>  8) & (n1 >> 16));               // b40b48
  n4 ^= (uint32_t) ((n1 >> 29) & (n2 >>  1));               // b61b65
  n4 ^= (uint32_t) ((n2 >>  4) & (n2 >> 20));               // b68b84
  n4 ^= (uint32_t) ((n0 >> 22) & (n0 >> 24) & (n0 >> 25));  // b22b24b25
  n4 ^= (uint32_t) ((n2 >>  6) & (n2 >> 14) & (n2 >> 18));  // b70b78b82
  n4 ^= (uint32_t) ((n2 >> 24) & (n2 >> 28) & (n2 >> 29) & (n2 >> 31));
                                                            // b88b92b93b95
  // shift the NFSR by 32 bits
  for (i = 0; i < 3; i++) nptr[i] = nptr[i+1];
  nptr[3] = n4;
  
  // f-function (update of LSFR)
  // shift distances: 6 7 17
  
  l4  = (uint32_t) (l0 ^ (l0 >> 7) ^ ((l1 ^ l2) >> 6));     // s0 s7 s38 s70
  l4 ^= (uint32_t) ((l2 >> 17) ^ l3);                       // s81 s96
  
  // shift the LFSR by 32 bits
  for (i = 0; i < 3; i++) lptr[i] = lptr[i+1];
  lptr[3] = l4;
  
  // h-function (pre-output bits)
  // shift distances NFSR: 2 4 9 12 13 15 25 31
  // shift distances LFSR: 8 10 13 15 20 28 29 30

  y  = (uint32_t) ((n0 >>  2) ^ (n0 >> 15));                // b2 b15
  y ^= (uint32_t) ((n1 >>  4) ^ (n1 >> 13));                // b36 b45
  y ^= (uint32_t) ((n2      ) ^ (n2 >>  9));                // b64 b73
  y ^= (uint32_t) ((n2 >> 25) ^ (l2 >> 29));                // b89 s93
  y ^= (uint32_t) ((n0 >> 12) & (l0 >>  8));                // x0x1 = b12s8
  y ^= (uint32_t) ((l0 >> 13) & (l0 >> 20));                // x2x3 = s13s20
  y ^= (uint32_t) ((n2 >> 31) & (l1 >> 10));                // x4x5 = b95s42
  y ^= (uint32_t) ((l1 >> 28) & (l2 >> 15));                // x6x7 = s60s79
  y ^= (uint32_t) ((n0 >> 12) & (n2 >> 31) & (l2 >> 30));   // x0x4x8=b12b95s94
  
  return y;
}


// The 3rd version of the Pre-Output Generator is based on the source code in
// Section 3.1.6 of the Eprint paper "Software Evaluation of Grain-128AEAD for
// Embedded Platforms" by Maximov and Hell (Paper 2020/659), but adapted for
// 64-bit platforms. The function shifts both the LSFR and the NFSR 32 bits and
// returns 32 pre-output bits.

uint32_t grain_keystr32_V3(grain_ctx *grain)
{
  uint32_t *lptr = grain->lfsr;
  uint32_t *nptr = grain->nfsr;
  uint32_t l4, n4 = lptr[0], y = nptr[2];
  uint32_t t0, t1, t2, t3, t4;  // temporary values for g-function
  uint32_t y0, y1, y2, y3;      // temporary values for h-function
  
  // f-function (update of LSFR) + part of h-function (pre-output bits)
  // shift distances: 6 7 17
  // shift distances for h-function: 8 10 13 15 20 28 29 30
  
  l4  = lptr[0] ^ lptr[3];      // s0 s96
  shift_reg128(lptr, 6);        // LFSR shifted 6 bits
  l4 ^= lptr[1] ^ lptr[2];      // s38 s70
  shift_reg128(lptr, 1);        // LFSR shifted 7 bits
  l4 ^= lptr[0];                // s7
  shift_reg128(lptr, 1);        // LFSR shifted 8 bits
  y0 = lptr[0];                 // x0x1 = b12s8 --> y0 used
  shift_reg128(lptr, 2);        // LFSR shifted 10 bits
  y1 = lptr[1];                 // x4x5 = b95s42 --> y1 used
  shift_reg128(lptr, 3);        // LFSR shifted 13 bits
  y2 = lptr[0];                 // x2x3 = s13s20 --> y2 used
  shift_reg128(lptr, 2);        // LFSR shifted 15 bits
  y3 = lptr[2];                 // x6x7 = s60s79 --> y3 used
  shift_reg128(lptr, 2);        // LFSR shifted 17 bits
  l4 ^=  lptr[2];               // s81
  shift_reg128(lptr, 3);        // LFSR shifted 20 bits
  y ^= y2 & lptr[0];            // x2x3 = s13s20 --> y2 free
  shift_reg128(lptr, 8);        // LFSR shifted 28 bits
  y ^= y3 & lptr[1];            // x6x7 = s60s79 --> y3 free
  shift_reg128(lptr, 1);        // LFSR shifted 29 bits
  y ^= lptr[2];                 // s93
  shift_reg128(lptr, 1);        // LFSR shifted 30 bits
  y2 = lptr[2];                 // x0x4x8 = b12b95s94 --> y2 used
  shift_reg128(lptr, 2);        // LFSR shifted 32 bits
  lptr[3] = l4;
  
  // g-function (update of NSFR) + part of h-function (pre-output bits)
  // shift distances: 1 3 4 6 8 11 13 14 16 17 18 20 22 24 25 26 27 28 29 31
  // shift distances for h-function: 2 4 9 12 13 15 25 31
  
  n4 ^= nptr[0] ^ nptr[3];      // s0 b0 b96
  shift_reg128(nptr, 1);        // NFSR shifted 1 bit
  t0 = nptr[2];                 // b61b65 --> t0 used
  shift_reg128(nptr, 1);        // NFSR shifted 2 bits
  y ^= nptr[0];                 // b2
  shift_reg128(nptr, 1);        // NFSR shifted 3 bits
  n4 ^= nptr[0] & nptr[2];      // b3b67
  shift_reg128(nptr, 1);        // NFSR shifted 4 bits
  t1 = nptr[2];                 // b68b84 --> t1 used
  y ^= nptr[1];                 // b36
  shift_reg128(nptr, 2);        // NFSR shifted 6 bits
  t2 = nptr[2];                 // b70b78b82 --> t2 used
  shift_reg128(nptr, 2);        // NFSR shifted 8 bits
  t3 = nptr[1];                 // b40b48 --> t3 used
  shift_reg128(nptr, 1);        // NFSR shifted 9 bits
  y ^= nptr[2];                 // b73
  shift_reg128(nptr, 2);        // NFSR shifted 11 bits
  t4 = nptr[0];                 // b11b13 --> t4 used
  shift_reg128(nptr, 1);        // NFSR shifted 12 bits
  y ^= y0 & nptr[0];            // x0x1 = b12s8 --> y0 free
  y2 &= nptr[0];                // x0x4x8 = b12b95s94
  shift_reg128(nptr, 1);        // NFSR shifted 13 bits
  n4 ^= t4 & nptr[0];           // b11b13 --> t4 free
  y ^= nptr[1];                 // b45
  shift_reg128(nptr, 1);        // NFSR shifted 14 bits
  t2 &= nptr[2];                // b70b78b82
  shift_reg128(nptr, 1);        // NFSR shifted 15 bits
  y ^= nptr[0];                 // b15
  shift_reg128(nptr, 1);        // NFSR shifted 16 bits
  n4 ^= t3 & nptr[1];           // b40b48 --> t3 free
  shift_reg128(nptr, 1);        // NFSR shifted 17 bits
  t3 = nptr[0];                 // b17b18 --> t3 used
  shift_reg128(nptr, 1);        // NFSR shifted 18 bits
  n4 ^= t3 & nptr[0];           // b17b18 --> t3 free
  n4 ^= t2 & nptr[2];           // b70b78b82 --> t2 free
  shift_reg128(nptr, 2);        // NFSR shifted 20 bits
  n4 ^= t1 & nptr[2];           // b68b84 --> t1 free
  shift_reg128(nptr, 2);        // NFSR shifted 22 bits
  t1 = nptr[0];                 // b22b24b25 --> t1 used
  shift_reg128(nptr, 2);        // NFSR shifted 24 bits
  n4 ^= nptr[1];                // b56
  t1 &= nptr[0];                // b22b24b25
  t2 = nptr[2];                 // b88b92b93b95 --> t2 used
  shift_reg128(nptr, 1);        // NFSR shifted 25 bits
  n4 ^= t1 & nptr[0];           // b22b24b25 --> t1 free
  y ^= nptr[2];                 // b89
  shift_reg128(nptr, 1);        // NFSR shifted 26 bits
  n4 ^= nptr[0];                // b26
  shift_reg128(nptr, 1);        // NFSR shifted 27 bits
  n4 ^= nptr[2];                // b91
  n4 ^= nptr[0] & nptr[1];      // b27b59
  shift_reg128(nptr, 1);        // NFSR shifted 28 bits
  t2 &= nptr[2];                // b88b92b93b95
  shift_reg128(nptr, 1);        // NFSR shifted 29 bits
  n4 ^= t0 & nptr[1];           // b61b65 --> t0 free
  t2 &= nptr[2];                // b88b92b93b95
  shift_reg128(nptr, 2);        // NFSR shifted 31 bits
  n4 ^= t2 & nptr[2];           // b88b92b93b95 --> t2 free
  y ^= y1 & nptr[2];            // x4x5 = b95s42 --> y1 free
  y ^= y2 & nptr[2];            // x0x4x8 = b12b95s94 --> y2 free
  shift_reg128(nptr, 1);        // NFSR shifted 32 bits
  nptr[3] = n4;
  
  return y;
}


// Simple test function for Pre-Output Generator.

void grain128_test_cipher(void)
{
  grain_ctx grainctx;
  grain_ctx *grain = &grainctx;
  uint8_t iv[12]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
  uint8_t key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
  uint32_t ks32;
  int i;
  
  /*
  // load key and IV along with padding
  memcpy(grain->nfsr, key, 16);
  memcpy(grain->lfsr, iv, 12);
  L32(12) = 0x7fffffffUL;
  printf("Version 1 (V1) of grain_keystr32():\n");
  print_grain(grain);
  // test V1 of grain_keystr32()
  for (i = -10; i < 2; i++) {
    ks32 = grain_keystr32_V1(grain);
    // printf("%08lx ", ks32);
    L32(12) ^= ks32;
    N32(12) ^= ks32;
    if (i < 0) continue;
    L32(12) ^= ((uint32_t *) key)[i+2];
    N32(12) ^= ((uint32_t *) key)[i];
  }
  print_grain(grain);
  */
  
  // load key and IV along with padding
  memcpy(grain->nfsr, key, 16);
  memcpy(grain->lfsr, iv, 12);
  grain->lfsr[3] = 0x7fffffffUL;
  printf("Version 2 (V2) of grain_keystr32():\n");
  print_grain(grain);
  // test V2 of grain_keystr32()
  for (i = -10; i < 2; i++) {
    ks32 = grain_keystr32_V2(grain);
    // printf("%08lx ", ks32);
    grain->lfsr[3] ^= ks32;
    grain->nfsr[3] ^= ks32;
    if (i < 0) continue;
    grain->lfsr[3] ^= ((uint32_t *) key)[i+2];
    grain->nfsr[3] ^= ((uint32_t *) key)[i];
  }
  print_grain(grain);
  
  // load key and IV along with padding
  memcpy(grain->nfsr, key, 16);
  memcpy(grain->lfsr, iv, 12);
  grain->lfsr[3] = 0x7fffffffUL;
  printf("Version 3 (V3) of grain_keystr32():\n");
  print_grain(grain);
  // test V3 of grain_keystr32()
  for (i = -10; i < 2; i++) {
    ks32 = grain_keystr32_V3(grain);
    // printf("%08lx ", ks32);
    grain->lfsr[3] ^= ks32;
    grain->nfsr[3] ^= ks32;
    if (i < 0) continue;
    grain->lfsr[3] ^= ((uint32_t *) key)[i+2];
    grain->nfsr[3] ^= ((uint32_t *) key)[i];
  }
  print_grain(grain);
  
  // Expected result
  // ---------------
  // Version 1 (V1) of grain_keystr32():
  // LFSR: 03020100 07060504 0b0a0908 7fffffff
  // NFSR: 03020100 07060504 0b0a0908 0f0e0d0c
  // LFSR: e47cf439 678005bb 12479c19 113b059a
  // NFSR: 7417c217 467fd30c 9da67318 7ebd7b55
  // Version 2 (V2) of grain_keystr32():
  // LFSR: 03020100 07060504 0b0a0908 7fffffff
  // NFSR: 03020100 07060504 0b0a0908 0f0e0d0c
  // LFSR: e47cf439 678005bb 12479c19 113b059a
  // NFSR: 7417c217 467fd30c 9da67318 7ebd7b55
  // Version 3 (V3) of grain_keystr32():
  // LFSR: 03020100 07060504 0b0a0908 7fffffff
  // NFSR: 03020100 07060504 0b0a0908 0f0e0d0c
  // LFSR: e47cf439 678005bb 12479c19 113b059a
  // NFSR: 7417c217 467fd30c 9da67318 7ebd7b55
}


///////////////////////////////////////////////////////////////////////////////
#else ///////////// IMPLEMENTATION FOR 8, 16 AND 32-BIT PLATFORMS /////////////
///////////////////////////////////////////////////////////////////////////////


// The 1st version of the Pre-Output Generator is based on the source code in
// `grain128aead-v2_opt.cpp` of the `x64` implementation from the designers,
// but adapted for 8/16/32-bit platforms. This version is only suitable for
// microcontrollers that can handle unaligned memory accesses, such as ARMv7-M
// (e.g. Cortex-M3 and M4), but not MSP430. The function shifts both the LSFR
// and NFSR 16 bits and returns 16 pre-output bits.

uint16_t grain_keystr16_V1(grain_ctx *grain)
{
  uint16_t ln, nn, y;
  
  ln  = (uint16_t) (L32(0) ^ L32(12) ^ (L32(0) >> 7) ^ (L32(4) >> 6));
  ln ^= (uint16_t) ((L32(8) >> 6) ^ (L32(10) >> 1));
  
  y  = (uint16_t) ((L32( 1) >> 5) & (L32( 2) >> 4));
  y ^= (uint16_t) ((L32( 7) >> 4) & (L32( 9) >> 7));
  y ^= (uint16_t) ((N32(11) >> 7) & (L32( 5) >> 2) ^ (N32(11) >> 1));
  y ^= (uint16_t) ((N32( 1) >> 4) & (N32(11) >> 7) & (L32(11) >> 6));
  y ^= (uint16_t) ((N32( 1) >> 4) & L32( 1));
  y ^= (uint16_t) ((L32(11) >> 5) ^ (N32( 0) >> 2) ^ (N32( 1) >> 7));
  y ^= (uint16_t) ((N32( 4) >> 4) ^ (N32( 5) >> 5) ^  N32( 8) ^ (N32(9) >> 1));
  
  nn  = (uint16_t) (L32( 0) ^ N32( 0) ^ N32( 7) ^ N32(12) ^ (N32(5) & N32(6)));
  nn ^= (uint16_t) (N32(11) & (N32(11) >> 4) & (N32(11) >> 5) & (N32(11) >> 7));
  nn ^= (uint16_t) (N32(11) >> 3);
  nn ^= (uint16_t) ((N32( 0) >> 3) & (N32( 8) >> 3));
  nn ^= (uint16_t) ((N32( 1) >> 3) & (N32( 1) >> 5));
  nn ^= (uint16_t) ((N32( 2) >> 1) & (N32( 2) >> 2));
  nn ^= (uint16_t) ((N32( 3) >> 3) & (N32( 7) >> 3));
  nn ^= (uint16_t) ((N32( 3) >> 2));
  nn ^= (uint16_t) ((N32( 7) >> 5) & (N32( 8) >> 1));
  nn ^= (uint16_t) ((N32( 8) >> 4) & (N32(10) >> 4));
  nn ^= (uint16_t) ((N32( 2) >> 6) & N32( 3) & (N32( 3) >> 1));
  nn ^= (uint16_t) ((N32( 8) >> 6) & (N32( 9) >> 6) & (N32(10) >> 2));
  
  memcpy(((uint16_t*) grain->lfsr), ((uint16_t*) grain->lfsr) + 1, 30);
  ((uint16_t*) grain->lfsr)[7] = ln;
  ((uint16_t*) grain->nfsr)[7] = nn;
  
  return y;
}


// The 2nd version of the Pre-Output Generator is similar to the 1st version
// but ensures that all memory accesses (e.g. loads and stores of words from
// are LFSR and NFSR) are properly aligned. The function shifts both the LSFR
// and the NFSR 16 bits and returns 16 pre-output bits.

uint16_t grain_keystr16_V2(grain_ctx *grain)
{
  uint16_t *lptr = (uint16_t *) grain->lfsr;
  uint16_t *nptr = (uint16_t *) grain->nfsr;
  uint16_t l8, n8, y;
  int i;
  
  uint32_t l0 = (((uint32_t) lptr[1]) << 16) | lptr[0];
  uint32_t l1 = (((uint32_t) lptr[2]) << 16) | lptr[1];
  uint32_t l2 = (((uint32_t) lptr[3]) << 16) | lptr[2];
  uint32_t l3 = (((uint32_t) lptr[4]) << 16) | lptr[3];
  uint32_t l4 = (((uint32_t) lptr[5]) << 16) | lptr[4];
  uint32_t l5 = (((uint32_t) lptr[6]) << 16) | lptr[5];
  uint32_t l6 = (((uint32_t) lptr[7]) << 16) | lptr[6];
  // uint32_t l7 = (((uint32_t) lptr[7]));
  
  uint32_t n0 = (((uint32_t) nptr[1]) << 16) | nptr[0];
  uint32_t n1 = (((uint32_t) nptr[2]) << 16) | nptr[1];
  uint32_t n2 = (((uint32_t) nptr[3]) << 16) | nptr[2];
  uint32_t n3 = (((uint32_t) nptr[4]) << 16) | nptr[3];
  uint32_t n4 = (((uint32_t) nptr[5]) << 16) | nptr[4];
  uint32_t n5 = (((uint32_t) nptr[6]) << 16) | nptr[5];
  uint32_t n6 = (((uint32_t) nptr[7]) << 16) | nptr[6];
  // uint32_t n7 = (((uint32_t) nptr[7]));
  
  // g-function (update of NSFR)
  // shift distances: 1 2 3 4 6 8 9 10 11 12 13 14 15
  
  n8  = (uint16_t) (l0 ^ n0 ^ (n1 >> 10));                  // s0 b0 b26
  n8 ^= (uint16_t) ((n3 >> 8) ^ (n5 >> 11) ^ n6);           // b56 b91 b96
  n8 ^= (uint16_t) ((n0 & n4) >> 3);                        // b3b67
  n8 ^= (uint16_t) ((n0 >> 11) & (n0 >> 13));               // b11b13
  n8 ^= (uint16_t) ((n1 >>  1) & (n1 >>  2));               // b17b18
  n8 ^= (uint16_t) ((n1 & n3) >> 11);                       // b27b59
  n8 ^= (uint16_t) ((n2 >>  8) & (n3      ));               // b40b48
  n8 ^= (uint16_t) ((n3 >> 13) & (n4 >>  1));               // b61b65
  n8 ^= (uint16_t) ((n4 & n5) >>  4);                       // b68b84
  n8 ^= (uint16_t) ((n1 >>  6) & (n1 >>  8) & (n1 >>  9));  // b22b24b25
  n8 ^= (uint16_t) ((n4 >>  6) & (n4 >> 14) & (n5 >>  2));  // b70b78b82
  n8 ^= (uint16_t) ((n5 >>  8) & (n5 >> 12) & (n5 >> 13) & (n5 >> 15));
                                                            // b88b92b93b95
  // shift the NFSR by 16 bits
  for (i = 0; i < 7; i++) nptr[i] = nptr[i+1];
  nptr[7] = n8;
  
  // f-function (update of LSFR)
  // shift distances: 1 6 7
  
  l8  = (uint16_t) (l0 ^ (l0 >> 7) ^ ((l2 ^ l4) >> 6));     // s0 s7 s38 s70
  l8 ^= (uint16_t) ((l5 >> 1) ^ l6);                        // s81 s96
  
  // shift the LFSR by 16 bits
  for (i = 0; i < 7; i++) lptr[i] = lptr[i+1];
  lptr[7] = l8;
  
  // h-function (pre-output bits)
  // shift distances NFSR: 2 4 9 12 13 15
  // shift distances LFSR: 4 8 10 12 13 14 15
  
  y  = (uint16_t) ((n0 >>  2) ^ (n0 >> 15));                // b2 b15
  y ^= (uint16_t) ((n2 >>  4) ^ (n2 >> 13));                // b36 b45
  y ^= (uint16_t) ((n4      ) ^ (n4 >>  9));                // b64 b73
  y ^= (uint16_t) ((n5 >>  9) ^ (l5 >> 13));                // b89 s93
  y ^= (uint16_t) ((n0 >> 12) & (l0 >>  8));                // x0x1 = b12s8
  y ^= (uint16_t) ((l0 >> 13) & (l1 >>  4));                // x2x3 = s13s20
  y ^= (uint16_t) ((n5 >> 15) & (l2 >> 10));                // x4x5 = b95s42
  y ^= (uint16_t) ((l3 >> 12) & (l4 >> 15));                // x6x7 = s60s79
  y ^= (uint16_t) ((n0 >> 12) & (n5 >> 15) & (l5 >> 14));   // x0x4x8=b12b95s94
  
  return y;
}


// The 3rd version of the Pre-Output Generator is based on the source code in
// Section 3.1.6 of the Eprint paper "Software Evaluation of Grain-128AEAD for
// Embedded Platforms" by Maximov and Hell (Paper 2020/659). The function
// shifts both the LSFR and the NFSR 16 bits and returns 16 pre-output bits.

uint16_t grain_keystr16_V3(grain_ctx *grain)
{
  uint16_t *lptr = (uint16_t *) grain->lfsr;
  uint16_t *nptr = (uint16_t *) grain->nfsr;
  uint16_t l8, n8 = lptr[0], y = nptr[4];
  uint16_t t0, t1, t2, t3;  // temporary values for g-function
  uint16_t y0, y1, y2, y3;  // temporary values for h-function
  
  // f-function (update of LSFR) + part of h-function (pre-output bits)
  // shift distances: 1 6 7
  // shift distances for h-function: 4 8 10 12 13 14 15
  
  l8 = lptr[0] ^ lptr[6];       // s0 s96
  shift_reg128(lptr, 1);        // LFSR shifted 1 bits
  l8 ^= lptr[5];                // s81
  shift_reg128(lptr, 3);        // LFSR shifted 4 bits
  y0 = lptr[1];                 // x2x3 = s13s20 --> y0 used
  shift_reg128(lptr, 2);        // LFSR shifted 6 bits
  l8 ^= lptr[2] ^ lptr[4];      // s38 s70
  shift_reg128(lptr, 1);        // LFSR shifted 7 bits
  l8 ^= lptr[0];                // s7
  shift_reg128(lptr, 1);        // LFSR shifted 8 bits
  y1 = lptr[0];                 // x0x1 = b12s8 --> y1 used
  shift_reg128(lptr, 2);        // LFSR shifted 10 bits
  y2 = lptr[2];                 // x4x5 = b95s42 --> y2 used
  shift_reg128(lptr, 2);        // LFSR shifted 12 bits
  y3 = lptr[3];                 // x6x7 = s60s79 --> y3 used
  shift_reg128(lptr, 1);        // LFSR shifted 13 bits
  y ^= y0 & lptr[0];            // x2x3 = s13s20 --> y0 free
  y ^= lptr[5];                 // s93
  shift_reg128(lptr, 1);        // LFSR shifted 14 bits
  y0 = lptr[5];                 // x0x4x8 = b12b95s94 -> y0 used
  shift_reg128(lptr, 1);        // LFSR shifted 15 bits
  y ^= y3 & lptr[4];            // x6x7 = s60s79 --> y3 free
  shift_reg128(lptr, 1);        // LFSR shifted 16 bits
  lptr[7] = l8;
  
  // g-function (update of NSFR) + part of h-function (pre-output bits)
  // shift distances: 1 2 3 4 6 8 9 10 11 12 13 14 15
  // shift distances for h-function: 2 4 9 12 13 15
  
  n8 ^= nptr[0] ^ nptr[6];      // b0 b96
  t0 = nptr[3];                 // b40b48 --> t0 used
  shift_reg128(nptr, 1);        // NFSR shifted 1 bits
  t1 = nptr[1];                 // b17b18 --> t1 used
  t2 = nptr[4];                 // b61b65 --> t2 used
  shift_reg128(nptr, 1);        // NFSR shifted 2 bits
  n8 ^= t1 & nptr[1];           // b17b18 --> t1 free
  t1 = nptr[5];                 // b70b78b82 --> t1 used
  y ^= nptr[0];                 // b2
  shift_reg128(nptr, 1);        // NFSR shifted 3 bits
  n8 ^= nptr[0] & nptr[4];      // b3b67
  shift_reg128(nptr, 1);        // NFSR shifted 4 bits
  n8 ^= nptr[4] & nptr[5];      // b68b84
  y ^= nptr[2];                 // b36
  shift_reg128(nptr, 2);        // NFSR shifted 6 bits
  t1 &= nptr[4];                // b70b78b82
  t3 = nptr[1];                 // b22b24b25 --> t3 used
  shift_reg128(nptr, 2);        // NFSR shifted 8 bits
  n8 ^= t0 & nptr[2];           // b40b48 --> t0 free
  n8 ^= nptr[3];                // b56
  t3 &= nptr[1];                // b22b24b25
  t0 = nptr[5];                 // b88b92b93b95 --> t0 used
  shift_reg128(nptr, 1);        // NFSR shifted 9 bits
  n8 ^= t3 & nptr[1];           // b22b24b25 --> t3 free
  y ^= nptr[4] ^ nptr[5];       // b73 b89
  shift_reg128(nptr, 1);        // NFSR shifted 10 bits
  n8 ^= nptr[1];                // b26
  shift_reg128(nptr, 1);        // NFSR shifted 11 bits
  n8 ^= nptr[5];                // b91
  n8 ^= nptr[1] & nptr[3];      // b27b59
  t3 = nptr[0];                 // b11b13 --> t3 used
  shift_reg128(nptr, 1);        // NFSR shifted 12 bits
  t0 &= nptr[5];                // b88b92b93b95
  y ^= y1 & nptr[0];            // x0x1 = b12s8 --> y1 free
  y0 &=  nptr[0];               // x0x4x8 = b12b95s94
  shift_reg128(nptr, 1);        // NFSR shifted 13 bits
  n8 ^= t3 & nptr[0];           // b11b13 --> t3 free
  n8 ^= t2 & nptr[3];           // b61b65 --> t2 free
  t0 &= nptr[5];                // b88b92b93b95
  y ^= nptr[2];                 // b45
  shift_reg128(nptr, 1);        // NFSR shifted 14 bits
  n8 ^= t1 & nptr[4];           // b70b78b82 --> t1 free
  shift_reg128(nptr, 1);        // NFSR shifted 15 bits
  n8 ^= t0 & nptr[5];           // b88b92b93b95 --> t0 free
  y ^= nptr[0];                 // b15
  y ^= y2 & nptr[5];            // x4x5 = b95s42 --> y2 free
  y ^= y0 & nptr[5];            // x0x4x8 = b12b95s94 --> y0 free
  shift_reg128(nptr, 1);        // NFSR shifted 16 bits
  nptr[7] = n8;
  
  return y;
}


// Simple test function for Pre-Output Generator.

void grain128_test_cipher(void)
{
  grain_ctx grainctx;
  grain_ctx *grain = &grainctx;
  uint8_t iv[12]  = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
  uint8_t key[16] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
  uint16_t ks16;
  int i;
  
  // 1st test: LSFR and NFSR initialized with all-0 words
  
  printf("Test 1 - C99 implementation:\n");
  memset(grain->nfsr, 0, 16);
  memset(grain->lfsr, 0, 12);
  grain->lfsr[3] = 0x7fffffffUL;
  print_grain(grain);
  for (i = -20; i < 4; i++) {
    ks16 = grain_keystr16_V2(grain);
    // printf("%04x ", ks16);
    ((uint16_t *) grain->lfsr)[7] ^= ks16;
    ((uint16_t *) grain->nfsr)[7] ^= ks16;
    if (i < 0) continue;
    ((uint16_t *) grain->lfsr)[7] ^= ((uint16_t *) key)[i+4];
    ((uint16_t *) grain->nfsr)[7] ^= ((uint16_t *) key)[i];
  }
  print_grain(grain);
  
#if defined(GRAIN_ASSEMBLER)
  printf("Test 1 - ASM implementation:\n");
  memset(grain->nfsr, 0, 16);
  memset(grain->lfsr, 0, 12);
  grain->lfsr[3] = 0x7fffffffUL;
  print_grain(grain);
  for (i = -20; i < 4; i++) {
    ks16 = grain_keystr16_asm(grain);
    // printf("%04x ", ks16);
    ((uint16_t *) grain->lfsr)[7] ^= ks16;
    ((uint16_t *) grain->nfsr)[7] ^= ks16;
    if (i < 0) continue;
    ((uint16_t *) grain->lfsr)[7] ^= ((uint16_t *) key)[i+4];
    ((uint16_t *) grain->nfsr)[7] ^= ((uint16_t *) key)[i];
  }
  print_grain(grain);
#endif
  
  // 2nd test: LSFR and NFSR initialized with byte-indices
  
  printf("Test 2 - C99 implementation:\n");
  memcpy(grain->nfsr, key, 16);
  memcpy(grain->lfsr, iv, 12);
  grain->lfsr[3] = 0x7fffffffUL;
  print_grain(grain);
  for (i = -20; i < 4; i++) {
    ks16 = grain_keystr16_V2(grain);
    // printf("%04x ", ks16);
    ((uint16_t *) grain->lfsr)[7] ^= ks16;
    ((uint16_t *) grain->nfsr)[7] ^= ks16;
    if (i < 0) continue;
    ((uint16_t *) grain->lfsr)[7] ^= ((uint16_t *) key)[i+4];
    ((uint16_t *) grain->nfsr)[7] ^= ((uint16_t *) key)[i];
  }
  print_grain(grain);
  
#if defined(GRAIN_ASSEMBLER)
  printf("Test 2 - ASM implementation:\n");
  memcpy(grain->nfsr, key, 16);
  memcpy(grain->lfsr, iv, 12);
  grain->lfsr[3] = 0x7fffffffUL;
  print_grain(grain);
  for (i = -20; i < 4; i++) {
    ks16 = grain_keystr16_asm(grain);
    // printf("%04x ", ks16);
    ((uint16_t *) grain->lfsr)[7] ^= ks16;
    ((uint16_t *) grain->nfsr)[7] ^= ks16;
    if (i < 0) continue;
    ((uint16_t *) grain->lfsr)[7] ^= ((uint16_t *) key)[i+4];
    ((uint16_t *) grain->nfsr)[7] ^= ((uint16_t *) key)[i];
  }
  print_grain(grain);
#endif
  
  // Expected result
  // ---------------
  // Test 1 - C99 implementation:
  // LFSR: 00000000 00000000 00000000 7fffffff
  // NFSR: 00000000 00000000 00000000 00000000
  // LFSR: 1e4e1dcc da5f39c5 9bb3f7d7 515fa75c
  // NFSR: ef299d57 49a4da82 b181cb96 f49a0baf
  // Test 1 - ASM implementation:
  // LFSR: 00000000 00000000 00000000 7fffffff
  // NFSR: 00000000 00000000 00000000 00000000
  // LFSR: 1e4e1dcc da5f39c5 9bb3f7d7 515fa75c
  // NFSR: ef299d57 49a4da82 b181cb96 f49a0baf
  // Test 2 - C99 implementation:
  // LFSR: 03020100 07060504 0b0a0908 7fffffff
  // NFSR: 03020100 07060504 0b0a0908 0f0e0d0c
  // LFSR: e47cf439 678005bb 12479c19 113b059a
  // NFSR: 7417c217 467fd30c 9da67318 7ebd7b55
  // Test 2 - ASM implementation:
  // LFSR: 03020100 07060504 0b0a0908 7fffffff
  // NFSR: 03020100 07060504 0b0a0908 0f0e0d0c
  // LFSR: e47cf439 678005bb 12479c19 113b059a
  // NFSR: 7417c217 467fd30c 9da67318 7ebd7b55
}


#endif
