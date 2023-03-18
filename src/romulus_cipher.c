///////////////////////////////////////////////////////////////////////////////
// romulus_cipher.c: C99 implementation + unit-test of Skinny-128-384 cipher //
// Version 1.0.0 (13-01-23), see <http://github.com/johgrolux/> for updates. //
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


#include <stdint.h>
#include <stdio.h>
#include <string.h>


#define NROUNDS 40


///////////////////////////////////////////////////////////////////////////////
/////////////////// SKINNY-128-384+ ENCRYPTION (FIX-SLICED) ///////////////////
///////////////////////////////////////////////////////////////////////////////


// The following macros are based on the source code in `skinny128.h` and
// `tk_schedule.h` of the `fixslice_opt32` implementation from the designers.

#define ROR(x, y) (((x) >> (y)) | ((x) << (32 - (y))))

#define SWAPMOVE(a, b, mask, n)         \
do {                                    \
  uint32_t tmp = (b ^ (a >> n)) & mask; \
  b ^= tmp;                             \
  a ^= (tmp << n);                      \
} while (0)


#define LE_LOAD(x, y)                   \
do {                                    \
  *(x) = (((uint32_t) (y)[3] << 24) |   \
  ((uint32_t) (y)[2] << 16)         |   \
  ((uint32_t) (y)[1] <<  8)         |   \
  (y)[0]);                              \
} while (0)


#define LE_STORE(x, y)          \
do {                            \
  (x)[0] =  (y)        & 0xff;  \
  (x)[1] = ((y) >>  8) & 0xff;  \
  (x)[2] = ((y) >> 16) & 0xff;  \
  (x)[3] =  (y) >> 24;          \
} while (0);


#define QUADRUPLE_ROUND_V1(state, rtk1, rtk2_3) \
do {                                            \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^=  (state[2] | state[3]);           \
  SWAPMOVE(state[3], state[0], 0x55555555, 0);  \
  state[0] ^= (rtk1)[0] ^ (rtk2_3)[0];          \
  state[1] ^= (rtk1)[1] ^ (rtk2_3)[1];          \
  state[2] ^= (rtk1)[2] ^ (rtk2_3)[2];          \
  state[3] ^= (rtk1)[3] ^ (rtk2_3)[3];          \
  mixcolumns_0(state);                          \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  state[3] ^=  (state[0] | state[1]);           \
  SWAPMOVE(state[1], state[2], 0x55555555, 0);  \
  state[0] ^= (rtk1)[4] ^ (rtk2_3)[4];          \
  state[1] ^= (rtk1)[5] ^ (rtk2_3)[5];          \
  state[2] ^= (rtk1)[6] ^ (rtk2_3)[6];          \
  state[3] ^= (rtk1)[7] ^ (rtk2_3)[7];          \
  mixcolumns_1(state);                          \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^= (state[2] | state[3]);            \
  SWAPMOVE(state[3], state[0], 0x55555555, 0);  \
  state[0] ^= (rtk1)[ 8] ^ (rtk2_3)[ 8];        \
  state[1] ^= (rtk1)[ 9] ^ (rtk2_3)[ 9];        \
  state[2] ^= (rtk1)[10] ^ (rtk2_3)[10];        \
  state[3] ^= (rtk1)[11] ^ (rtk2_3)[11];        \
  mixcolumns_2(state);                          \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  state[3] ^= (state[0] | state[1]);            \
  SWAPMOVE(state[1], state[2], 0x55555555, 0);  \
  state[0] ^= (rtk1)[12] ^ (rtk2_3)[12];        \
  state[1] ^= (rtk1)[13] ^ (rtk2_3)[13];        \
  state[2] ^= (rtk1)[14] ^ (rtk2_3)[14];        \
  state[3] ^= (rtk1)[15] ^ (rtk2_3)[15];        \
  mixcolumns_3(state);                          \
} while (0)


#if (defined(__AVR) || defined(__AVR__))
extern void skinny128384p_enc_avr(uint8_t *ctext, const uint8_t *ptext, \
  const uint32_t *rtk1, const uint32_t *rtk2_3);
#define skinny128384p_enc_asm(ctxt, ptxt, rtk1, rtk2_3) \
  skinny128384p_enc_avr((ctxt), (ptxt), (rtk1), (rtk2_3))
#define ROMULUS_ASSEMBLER
#endif

#if (defined(__MSP430__) || defined(__ICC430__))
extern void skinny128384p_enc_msp(uint8_t *ctext, const uint8_t *ptext, \
  const uint32_t *rtk1, const uint32_t *rtk2_3);
#define skinny128384p_enc_asm(ctxt, ptxt, rtk1, rtk2_3) \
  skinny128384p_enc_msp((ctxt), (ptxt), (rtk1), (rtk2_3))
#define ROMULUS_ASSEMBLER
#endif


// MixColumns operation for rounds i with (i % 4) == 0

void mixcolumns_0(uint32_t *state)
{
  uint32_t tmp;
  int i;
  
  for(i = 0; i < 4; i++) {
    tmp = ROR(state[i], 24) & 0x0c0c0c0c;
    state[i] ^= ROR(tmp, 30);
    tmp = ROR(state[i], 16) & 0xc0c0c0c0;
    state[i] ^= ROR(tmp,  4);
    tmp = ROR(state[i],  8) & 0x0c0c0c0c;
    state[i] ^= ROR(tmp,  2);
  }
}


// MixColumns operation for rounds i with (i % 4) == 1

void mixcolumns_1(uint32_t *state)
{
  uint32_t tmp;
  int i;

  for(i = 0; i < 4; i++) {
    tmp = ROR(state[i], 16) & 0x30303030;
    state[i] ^= ROR(tmp, 30);
    tmp = state[i] & 0x03030303;
    state[i] ^= ROR(tmp, 28);
    tmp = ROR(state[i], 16) & 0x30303030;
    state[i] ^= ROR(tmp,  2);
  }
}


// MixColumns operation for rounds i with (i % 4) == 2

void mixcolumns_2(uint32_t *state) {
  uint32_t tmp;
  int i;

  for(i = 0; i < 4; i++) {
    tmp = ROR(state[i],  8) & 0xc0c0c0c0;
    state[i] ^= ROR(tmp,  6);
    tmp = ROR(state[i], 16) & 0x0c0c0c0c;
    state[i] ^= ROR(tmp, 28);
    tmp = ROR(state[i], 24) & 0xc0c0c0c0;
    state[i] ^= ROR(tmp,  2);
  }
}


// MixColumns operation for rounds i with (i % 4) == 3

void mixcolumns_3(uint32_t *state)
{
  uint32_t tmp;
  int i;

  for(i = 0; i < 4; i++) {
    tmp = state[i] & 0x03030303;
    state[i] ^= ROR(tmp, 30);
    tmp = state[i] & 0x30303030;
    state[i] ^= ROR(tmp,  4);
    tmp = state[i] & 0x03030303;
    state[i] ^= ROR(tmp, 26);
  }
}


// Pack the input into the bitsliced representation.

void packing(uint32_t *out, const uint8_t *in)
{
  LE_LOAD(out, in);
  LE_LOAD(out + 1, in + 8);
  LE_LOAD(out + 2, in + 4);
  LE_LOAD(out + 3, in + 12);
  SWAPMOVE(out[0], out[0], 0x0a0a0a0a, 3);
  SWAPMOVE(out[1], out[1], 0x0a0a0a0a, 3);
  SWAPMOVE(out[2], out[2], 0x0a0a0a0a, 3);
  SWAPMOVE(out[3], out[3], 0x0a0a0a0a, 3);
  SWAPMOVE(out[2], out[0], 0x30303030, 2);
  SWAPMOVE(out[1], out[0], 0x0c0c0c0c, 4);
  SWAPMOVE(out[3], out[0], 0x03030303, 6);
  SWAPMOVE(out[1], out[2], 0x0c0c0c0c, 2);
  SWAPMOVE(out[3], out[2], 0x03030303, 4);
  SWAPMOVE(out[3], out[1], 0x03030303, 2);
}


// Unpack the input to a byte-wise representation.

void unpacking(uint8_t *out, uint32_t *in)
{
  SWAPMOVE(in[3], in[1], 0x03030303, 2);
  SWAPMOVE(in[3], in[2], 0x03030303, 4);
  SWAPMOVE(in[1], in[2], 0x0c0c0c0c, 2);
  SWAPMOVE(in[3], in[0], 0x03030303, 6);
  SWAPMOVE(in[1], in[0], 0x0c0c0c0c, 4);
  SWAPMOVE(in[2], in[0], 0x30303030, 2);
  SWAPMOVE(in[0], in[0], 0x0a0a0a0a, 3);
  SWAPMOVE(in[1], in[1], 0x0a0a0a0a, 3);
  SWAPMOVE(in[2], in[2], 0x0a0a0a0a, 3);
  SWAPMOVE(in[3], in[3], 0x0a0a0a0a, 3);
  LE_STORE(out, in[0]);
  LE_STORE(out + 8, in[1]);
  LE_STORE(out + 4, in[2]);
  LE_STORE(out + 12, in[3]);
}


// The 1st version of the fix-sliced Skinny-128-384+ encryption is based on the
// source code in `skinny128.c` of the `fixslice_opt32` implementation from the
// designers. This version is fully unrolled. The function encrypts a single
// block without any operation mode using SKINNY-128-384 with 40 rounds. The
// round-tweakeys RTK1 and RTK2_3 are given separately to take advantage of the
// fact that TK2 and TK3 remains the same through the entire encryption.
/*
void skinny128384p_enc_c99_V1(uint8_t *ctext, const uint8_t *ptext, \
  const uint32_t *rtk1, const uint32_t *rtk2_3)
{
  uint32_t state[4];  // 128-bit state

  packing(state, ptext);    // from byte to bitsliced representation
  QUADRUPLE_ROUND_V1(state, rtk1,      rtk2_3      );
  QUADRUPLE_ROUND_V1(state, rtk1 + 16, rtk2_3 +  16);
  QUADRUPLE_ROUND_V1(state, rtk1 + 32, rtk2_3 +  32);
  QUADRUPLE_ROUND_V1(state, rtk1 + 48, rtk2_3 +  48);
  QUADRUPLE_ROUND_V1(state, rtk1     , rtk2_3 +  64);
  QUADRUPLE_ROUND_V1(state, rtk1 + 16, rtk2_3 +  80);
  QUADRUPLE_ROUND_V1(state, rtk1 + 32, rtk2_3 +  96);
  QUADRUPLE_ROUND_V1(state, rtk1 + 48, rtk2_3 + 112);
  QUADRUPLE_ROUND_V1(state, rtk1     , rtk2_3 + 128);
  QUADRUPLE_ROUND_V1(state, rtk1 + 16, rtk2_3 + 144);
  unpacking(ctext, state);  // from bitsliced to byte representation
}
*/


#define EVEN_ROUND(state)                       \
do {                                            \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  state[1] ^=  (state[2] | state[3]);           \
  SWAPMOVE(state[3], state[0], 0x55555555, 0);  \
} while (0)


#define ODD_ROUND(state)                        \
do {                                            \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  state[3] ^= ~(state[0] | state[1]);           \
  SWAPMOVE(state[3], state[2], 0x55555555, 1);  \
  SWAPMOVE(state[2], state[1], 0x55555555, 1);  \
  state[1] ^= ~(state[2] | state[3]);           \
  SWAPMOVE(state[0], state[3], 0x55555555, 1);  \
  SWAPMOVE(state[1], state[0], 0x55555555, 1);  \
  state[3] ^=  (state[0] | state[1]);           \
  SWAPMOVE(state[1], state[2], 0x55555555, 0);  \
} while (0)


#define ADD_RTWEAKEY(state, rtk1, rtk2_3, i)    \
do {                                            \
  state[0] ^= (rtk1)[i    ] ^ (rtk2_3)[i    ];  \
  state[1] ^= (rtk1)[(i)+1] ^ (rtk2_3)[(i)+1];  \
  state[2] ^= (rtk1)[(i)+2] ^ (rtk2_3)[(i)+2];  \
  state[3] ^= (rtk1)[(i)+3] ^ (rtk2_3)[(i)+3];  \
} while (0)


#define QUADRUPLE_ROUND_V2(state, rtk1, rtk2_3) \
do {                                            \
  EVEN_ROUND(state);                            \
  ADD_RTWEAKEY(state, rtk1, rtk2_3, 0);         \
  mixcolumns_0(state);                          \
  ODD_ROUND(state);                             \
  ADD_RTWEAKEY(state, rtk1, rtk2_3, 4);         \
  mixcolumns_1(state);                          \
  EVEN_ROUND(state);                            \
  ADD_RTWEAKEY(state, rtk1, rtk2_3, 8);         \
  mixcolumns_2(state);                          \
  ODD_ROUND(state);                             \
  ADD_RTWEAKEY(state, rtk1, rtk2_3, 12);        \
  mixcolumns_3(state);                          \
} while (0)


// The 2nd version of the fix-sliced Skinny-128-384+ encryption is similar to
// the 1st version above, but executes the quadruple-rounds in a loop with 10
// iterations and uses sub-macros for even/odd rounds. The function encrypts a
// single block without any operation mode using SKINNY-128-384 with 40 rounds.
// The round-tweakeys RTK1 and RTK2_3 are given separately to take advantage of
// the fact that TK2 and TK3 remains the same through the entire encryption.

void skinny128384p_enc_c99_V2(uint8_t *ctext, const uint8_t *ptext, \
  const uint32_t *rtk1, const uint32_t *rtk2_3)
{
  uint32_t state[4];  // 128-bit state
  int i;

  packing(state, ptext);    // from byte to bitsliced representation
  for (i = 0; i < 4*NROUNDS; i += 4*4) {
    QUADRUPLE_ROUND_V2(state, rtk1 + (i & 0x3f), rtk2_3 + i);
  }
  unpacking(ctext, state);  // from bitsliced to byte representation
}


// Print plain/ciphertext-words or key-words of Skinny-128-384+ in Hex format.

static void print_words(const uint32_t *w, int len)
{
  uint8_t buffer[85], byte;
  int i, j, k = 0;

  // printf("%08lx %08lx %08lx %08lx\n", w[0], w[1], w[2], w[3]);

  for (i = 0; i < len; i++) {
    for (j = 7; j >= 0; j--) {
      byte = (w[i] >> 4*j) & 0xf;
      // replace 87 by 55 to get uppercase letters
      buffer[k++] = byte + ((byte < 10) ? 48 : 87);
    }
    buffer[k++] = ' ';
  }
  buffer[k-1] = '\0';

  printf("%s\n", buffer);
}


// Simple test function for the fix-sliced Skinny-128-384+ encryption.

void romulus_test_cipher(void)
{
  uint8_t ptxt[16], ctxt[16];
  uint32_t rtk1[64];
  uint32_t rtk2_3[160];
  int i;

  for (i = 0; i < 256; i++) ((uint8_t *) rtk1)[i] = (uint8_t) i;
  for (i = 0; i < 640; i++) ((uint8_t *) rtk2_3)[i] = (uint8_t) i;

  // 1st test: plaintext is initialized with 0 bytes

  printf("Test 1 - C99 implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = 0;
  print_words((uint32_t *) ptxt, 4);
  skinny128384p_enc_c99_V2(ctxt, ptxt, rtk1, rtk2_3);  // encryption in C
  print_words((uint32_t *) ctxt, 4);

#if defined(ROMULUS_ASSEMBLER)
  printf("Test 1 - ASM implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = 0;
  print_words((uint32_t *) ptxt, 4);
  skinny128384p_enc_asm(ctxt, ptxt, rtk1, rtk2_3);  // encryption in ASM
  print_words((uint32_t *) ctxt, 4);
#endif

  // 2nd test: plaintext is initialized with byte-indeces

  printf("Test 2 - C99 implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = (uint8_t) i;
  print_words((uint32_t *) ptxt, 4);
  skinny128384p_enc_c99_V2(ctxt, ptxt, rtk1, rtk2_3);  // encryption in C
  print_words((uint32_t *) ctxt, 4);

#if defined(ROMULUS_ASSEMBLER)
  printf("Test 2 - ASM implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = (uint8_t)i;
  print_words((uint32_t *) ptxt, 4);
  skinny128384p_enc_asm(ctxt, ptxt, rtk1, rtk2_3);  // encryption in ASM
  print_words((uint32_t *) ctxt, 4);
#endif

  // Expected result for 40 rounds
  // -----------------------------
  // Test 1 - C99 implementation:
  // 00000000 00000000 00000000 00000000
  // 92929292 92929292 d3d3d3d3 d3d3d3d3
  // Test 1 - ASM implementation:
  // 00000000 00000000 00000000 00000000
  // 92929292 92929292 d3d3d3d3 d3d3d3d3
  // Test 2 - C99 implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c
  // a1493b4c 6a4f2e3b bd763677 78c7f23f
  // Test 2 - ASM implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c
  // a1493b4c 6a4f2e3b bd763677 78c7f23f
}
