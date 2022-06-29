///////////////////////////////////////////////////////////////////////////////
// giftcofb_cipher.c: Optimized C99 implementation of GIFT-128 block cipher. //
// Version 1.0.0 (30-05-22), see <http://github.com/johgrolux/> for updates. //
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


#define MAXROUNDS 40


///////////////////////////////////////////////////////////////////////////////
////////////////////// GIFT-128 KEY SCHEDULE (FIX-SLICED) /////////////////////
///////////////////////////////////////////////////////////////////////////////


// The followig macros are based on the source code in `giftb128.h` of the
// `opt32` implementation from the designers.

#define ROR(x, y) (((x) >> (y)) | ((x) << (32 - (y))))

#define SWAPMOVE(a, b, mask, n)         \
do {                                    \
  uint32_t tmp = (b ^ (a >> n)) & mask; \
  b ^= tmp;                             \
  a ^= (tmp << n);                      \
} while (0)


// The followig macros are based on the source code in `key_schedule.h` of the
// `opt32` implementation from the designers.

#define REARRANGE_RKEY_0(x)        \
do {                               \
  SWAPMOVE(x, x, 0x00550055,  9);  \
  SWAPMOVE(x, x, 0x000f000f, 12);  \
  SWAPMOVE(x, x, 0x00003333, 18);  \
  SWAPMOVE(x, x, 0x000000ff, 24);  \
} while(0)


#define REARRANGE_RKEY_1(x)        \
do {                               \
  SWAPMOVE(x, x, 0x11111111,  3);  \
  SWAPMOVE(x, x, 0x03030303,  6);  \
  SWAPMOVE(x, x, 0x000f000f, 12);  \
  SWAPMOVE(x, x, 0x000000ff, 24);  \
} while(0)


#define REARRANGE_RKEY_2(x)        \
do {                               \
  SWAPMOVE(x, x, 0x0000aaaa, 15);  \
  SWAPMOVE(x, x, 0x00003333, 18);  \
  SWAPMOVE(x, x, 0x0000f0f0, 12);  \
  SWAPMOVE(x, x, 0x000000ff, 24);  \
} while(0)


#define REARRANGE_RKEY_3(x)        \
do {                               \
  SWAPMOVE(x, x, 0x0a0a0a0a,  3);  \
  SWAPMOVE(x, x, 0x00cc00cc,  6);  \
  SWAPMOVE(x, x, 0x0000f0f0, 12);  \
  SWAPMOVE(x, x, 0x000000ff, 24);  \
} while(0)


#define KEY_UPDATE(x)                                        \
  ((((x) >> 12) & 0x0000000f) | (((x) & 0x00000fff) <<  4) | \
   (((x) >>  2) & 0x3fff0000) | (((x) & 0x00030000) << 14))


#define KEY_TRIPLE_UPDATE_0(x)                               \
  (ROR((x) & 0x33333333, 24)  | ROR((x) & 0xcccccccc, 16))


#define KEY_DOUBLE_UPDATE_1(x)                               \
  ((((x) >>  4) & 0x0f000f00) | (((x) & 0x0f000f00) <<  4) | \
   (((x) >>  6) & 0x00030003) | (((x) & 0x003f003f) <<  2))


#define KEY_TRIPLE_UPDATE_1(x)                               \
  ((((x) >>  6) & 0x03000300) | (((x) & 0x3f003f00) <<  2) | \
   (((x) >>  5) & 0x00070007) | (((x) & 0x001f001f) <<  3))


#define KEY_DOUBLE_UPDATE_2(x)                               \
  (ROR((x) & 0xaaaaaaaa, 24)  | ROR((x) & 0x55555555, 16))


#define KEY_TRIPLE_UPDATE_2(x)                               \
  (ROR((x) & 0x55555555, 24)  | ROR((x) & 0xaaaaaaaa, 20))


#define KEY_DOUBLE_UPDATE_3(x)                               \
  ((((x) >>  2) & 0x03030303) | (((x) & 0x03030303) <<  2) | \
   (((x) >>  1) & 0x70707070) | (((x) & 0x10101010) <<  3))


#define KEY_TRIPLE_UPDATE_3(x)                               \
  ((((x) >> 18) & 0x00003030) | (((x) & 0x01010101) <<  3) | \
   (((x) >> 14) & 0x0000c0c0) | (((x) & 0x0000e0e0) << 15) | \
   (((x) >>  1) & 0x07070707) | (((x) & 0x00001010) << 19))


#define KEY_DOUBLE_UPDATE_4(x)                               \
  ((((x) >>  4) & 0x0fff0000) | (((x) & 0x000f0000) << 12) | \
   (((x) >>  8) & 0x000000ff) | (((x) & 0x000000ff) << 8))


#define KEY_TRIPLE_UPDATE_4(x)                               \
  ((((x) >>  6) & 0x03ff0000) | (((x) & 0x003f0000) << 10) | \
   (((x) >>  4) & 0x00000fff) | (((x) & 0x0000000f) << 12))


// The followig macros are based on the source code in `endian.h` of the
// `opt32` implementation from the designers.

#define U32BIG(x)                                            \
  ((((x) & 0x000000FF) << 24) | (((x) & 0x0000FF00) <<  8) | \
   (((x) & 0x00FF0000) >>  8) | (((x) & 0xFF000000) >> 24))


#define U8BIG(x, y)            \
do {                           \
  (x)[0] =  (y) >> 24;         \
  (x)[1] = ((y) >> 16) & 0xff; \
  (x)[2] = ((y) >>  8) & 0xff; \
  (x)[3] =  (y)        & 0xff; \
} while (0)


// The 1st version of the generation of round-keys for fix-sliced GIFT-128 is
// based on the source code in `giftb128.c` of the `opt32` implementation from
// the designers. The first 20 round-keys are computed using the classical
// representation before being rearranged into fix-sliced representations
// depending on round numbers. The 60 remaining rkeys are directly computed in
// fix-scliced representations.

void gift128f_grk_c99_V1(uint32_t *rkey, const uint8_t *key)
{
  int i;

  // classical initialization
  rkey[0] = U32BIG(((uint32_t *) key)[3]);
  rkey[1] = U32BIG(((uint32_t *) key)[1]);
  rkey[2] = U32BIG(((uint32_t *) key)[2]);
  rkey[3] = U32BIG(((uint32_t *) key)[0]);

  // classical key-schedule for 20 round-keys
  for (int i = 0; i < 16; i += 2) {
    rkey[i+4] = rkey[i+1];
    rkey[i+5] = KEY_UPDATE(rkey[i]);
  }

  // transposition to fix-sliced representation
  for (i = 0; i < 20; i += 10) {
    REARRANGE_RKEY_0(rkey[i]);
    REARRANGE_RKEY_0(rkey[i+1]);
    REARRANGE_RKEY_1(rkey[i+2]);
    REARRANGE_RKEY_1(rkey[i+3]);
    REARRANGE_RKEY_2(rkey[i+4]);
    REARRANGE_RKEY_2(rkey[i+5]);
    REARRANGE_RKEY_3(rkey[i+6]);
    REARRANGE_RKEY_3(rkey[i+7]);
  }

  // fix-sliced key schedule for 60 round-keys
  for (i = 20; i < 2*MAXROUNDS; i += 10) {
    rkey[i] = rkey[i-19];
    rkey[i+1] = KEY_TRIPLE_UPDATE_0(rkey[i-20]);
    rkey[i+2] = KEY_DOUBLE_UPDATE_1(rkey[i-17]);
    rkey[i+3] = KEY_TRIPLE_UPDATE_1(rkey[i-18]);
    rkey[i+4] = KEY_DOUBLE_UPDATE_2(rkey[i-15]);
    rkey[i+5] = KEY_TRIPLE_UPDATE_2(rkey[i-16]);
    rkey[i+6] = KEY_DOUBLE_UPDATE_3(rkey[i-13]);
    rkey[i+7] = KEY_TRIPLE_UPDATE_3(rkey[i-14]);
    rkey[i+8] = KEY_DOUBLE_UPDATE_4(rkey[i-11]);
    rkey[i+9] = KEY_TRIPLE_UPDATE_4(rkey[i-12]);
    SWAPMOVE(rkey[i], rkey[i], 0x00003333, 16);
    SWAPMOVE(rkey[i], rkey[i], 0x55554444, 1);
    SWAPMOVE(rkey[i+1], rkey[i+1], 0x55551100, 1);
  }
}


// The 2nd version of the generation of round-keys for fix-sliced GIFT-128 is
// similar to the 1st version above, but computes all 80 round-keys are using
// the classical representation before being rearranged into fix-sliced
// representations depending on round numbers.

void gift128f_grk_c99_V2(uint32_t *rkey, const uint8_t *key)
{
  int i;

  // classical initialization
  rkey[0] = U32BIG(((uint32_t * ) key)[3]);
  rkey[1] = U32BIG(((uint32_t * ) key)[1]);
  rkey[2] = U32BIG(((uint32_t * ) key)[2]);
  rkey[3] = U32BIG(((uint32_t * ) key)[0]);

  // classical key-schedule for all round-keys
  for (i = 4; i < 2*MAXROUNDS; i += 2) {
    rkey[i] = rkey[i-3];
    rkey[i+1] = KEY_UPDATE(rkey[i-4]);
  }

  // transposition to fix-sliced representation
  for (i = 0; i < 80; i += 10) {
    REARRANGE_RKEY_0(rkey[i]);
    REARRANGE_RKEY_0(rkey[i+1]);
    REARRANGE_RKEY_1(rkey[i+2]);
    REARRANGE_RKEY_1(rkey[i+3]);
    REARRANGE_RKEY_2(rkey[i+4]);
    REARRANGE_RKEY_2(rkey[i+5]);
    REARRANGE_RKEY_3(rkey[i+6]);
    REARRANGE_RKEY_3(rkey[i+7]);
  }
}


///////////////////////////////////////////////////////////////////////////////
/////////////////////// GIFT-128 ENCRYPTION (FIX-SLICED) //////////////////////
///////////////////////////////////////////////////////////////////////////////


// The followig macros are based on the source code in `giftb128.h` of the
// `opt32` implementation from the designers.

#define BYTE_ROR_2(x) ((((x) >> 2) & 0x3f3f3f3f) | (((x) & 0x03030303) << 6))
#define BYTE_ROR_4(x) ((((x) >> 4) & 0x0f0f0f0f) | (((x) & 0x0f0f0f0f) << 4))
#define BYTE_ROR_6(x) ((((x) >> 6) & 0x03030303) | (((x) & 0x3f3f3f3f) << 2))

#define HALF_ROR_4(x) ((((x) >>  4) & 0x0fff0fff) | (((x) & 0x000f000f) << 12))
#define HALF_ROR_8(x) ((((x) >>  8) & 0x00ff00ff) | (((x) & 0x00ff00ff) << 8))
#define HALF_ROR_12(x) ((((x) >> 12) & 0x000f000f) | (((x) & 0x0fff0fff) << 4))

#define NIBBLE_ROR_1(x) ((((x) >> 1) & 0x77777777) | (((x) & 0x11111111) << 3))
#define NIBBLE_ROR_2(x) ((((x) >> 2) & 0x33333333) | (((x) & 0x33333333) << 2))
#define NIBBLE_ROR_3(x) ((((x) >> 3) & 0x11111111) | (((x) & 0x77777777) << 1))


#define SBOX(s0, s1, s2, s3) \
do {                         \
  s1 ^= s0 & s2;             \
  s0 ^= s1 & s3;             \
  s2 ^= s0 | s1;             \
  s3 ^= s2;                  \
  s1 ^= s3;                  \
  s3 ^= 0xffffffff;          \
  s2 ^= s0 & s1;             \
} while (0)


#define QUINTUPLE_ROUND(state, rkey, rconst)    \
do {                                            \
  SBOX(state[0], state[1], state[2], state[3]); \
  state[3] = NIBBLE_ROR_1(state[3]);            \
  state[1] = NIBBLE_ROR_2(state[1]);            \
  state[2] = NIBBLE_ROR_3(state[2]);            \
  state[1] ^= (rkey)[0];                        \
  state[2] ^= (rkey)[1];                        \
  state[0] ^= (rconst)[0];                      \
  SBOX(state[3], state[1], state[2], state[0]); \
  state[0] = HALF_ROR_4(state[0]);              \
  state[1] = HALF_ROR_8(state[1]);              \
  state[2] = HALF_ROR_12(state[2]);             \
  state[1] ^= (rkey)[2];                        \
  state[2] ^= (rkey)[3];                        \
  state[3] ^= (rconst)[1];                      \
  SBOX(state[0], state[1], state[2], state[3]); \
  state[3] = ROR(state[3], 16);                 \
  state[2] = ROR(state[2], 16);                 \
  SWAPMOVE(state[1], state[1], 0x55555555, 1);  \
  SWAPMOVE(state[2], state[2], 0x00005555, 1);  \
  SWAPMOVE(state[3], state[3], 0x55550000, 1);  \
  state[1] ^= (rkey)[4];                        \
  state[2] ^= (rkey)[5];                        \
  state[0] ^= (rconst)[2];                      \
  SBOX(state[3], state[1], state[2], state[0]); \
  state[0] = BYTE_ROR_6(state[0]);              \
  state[1] = BYTE_ROR_4(state[1]);              \
  state[2] = BYTE_ROR_2(state[2]);              \
  state[1] ^= (rkey)[6];                        \
  state[2] ^= (rkey)[7];                        \
  state[3] ^= (rconst)[3];                      \
  SBOX(state[0], state[1], state[2], state[3]); \
  state[3] = ROR(state[3], 24);                 \
  state[1] = ROR(state[1], 16);                 \
  state[2] = ROR(state[2], 8);                  \
  state[1] ^= (rkey)[8];                        \
  state[2] ^= (rkey)[9];                        \
  state[0] ^= (rconst)[4];                      \
  state[0] ^= state[3];                         \
  state[3] ^= state[0];                         \
  state[0] ^= state[3];                         \
} while (0)


// Round constants according to the fix-sliced representation
const uint32_t rconst[40] = {
  0x10000008, 0x80018000, 0x54000002, 0x01010181, 0x8000001f,
  0x10888880, 0x6001e000, 0x51500002, 0x03030180, 0x8000002f,
  0x10088880, 0x60016000, 0x41500002, 0x03030080, 0x80000027,
  0x10008880, 0x4001e000, 0x11500002, 0x03020180, 0x8000002b,
  0x10080880, 0x60014000, 0x01400002, 0x02020080, 0x80000021,
  0x10000080, 0x0001c000, 0x51000002, 0x03010180, 0x8000002e,
  0x10088800, 0x60012000, 0x40500002, 0x01030080, 0x80000006,
  0x10008808, 0xc001a000, 0x14500002, 0x01020181, 0x8000001a
};


#if (defined(__AVR) || defined(__AVR__))
extern void gift128f_enc_avr(uint8_t *ctxt, const uint8_t *ptxt, \
  const uint32_t *rkey);
extern void gift128f_grk_avr(uint32_t *rkey, const uint8_t *key);
#define gift128f_enc_asm(ctxt, ptxt, rkey) \
  gift128f_enc_avr((ctxt), (ptxt), (rkey))
#define gift128f_grk_asm(rkey, key) gift128f_grk_avr((rkey), (key));
#define GIFTCOFB_ASSEMBLER
#endif

#if (defined(__MSP430__) || defined(__ICC430__))
extern void gift128f_enc_msp(uint8_t *ctxt, const uint8_t *ptxt, \
  const uint32_t *rkey);
extern void gift128f_grk_msp(uint32_t *rkey, const uint8_t *key);
#define gift128f_enc_asm(ctxt, ptxt, rkey) \
  gift128f_enc_msp((ctxt), (ptxt), (rkey))
#define gift128f_grk_asm(rkey, key) gift128f_grk_msp((rkey), (key));
#define GIFTCOFB_ASSEMBLER
#endif


// Print plain/ciphertext-words or key-words of GIFT128 in Hex format.

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


// The fix-sliced implementation of the GIFT-128 encryption is based on the 
// source code in `giftb128.c` of the `opt32` implementation from the
// designers.

void gift128f_enc_c99(uint8_t *ctxt, const uint8_t *ptxt, const uint32_t *rkey)
{
  uint32_t state[4];
  int i;

  state[0] = U32BIG(((uint32_t *) ptxt)[0]);
  state[1] = U32BIG(((uint32_t *) ptxt)[1]);
  state[2] = U32BIG(((uint32_t *) ptxt)[2]);
  state[3] = U32BIG(((uint32_t *) ptxt)[3]);

  for (i = 0; i < MAXROUNDS; i += 5) {
    QUINTUPLE_ROUND(state, rkey + 2*i, rconst + i);
  }

  U8BIG(ctxt, state[0]);
  U8BIG(ctxt + 4, state[1]);
  U8BIG(ctxt + 8, state[2]);
  U8BIG(ctxt + 12, state[3]);
}


// Simple test function for the fix-sliced GIFT128 encryption.

void test_giftcofb(void)
{
  uint8_t ptxt[16], ctxt[16], key[16];
  uint32_t rkey[80];
  int i;

  for (i = 0; i < 16; i++) key[i] = (uint8_t) 128 + i;
  gift128f_grk_c99_V1(rkey, key);

  // 1st test: plaintext is initialized with 0 bytes

  printf("Test 1 - C99 implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = 0;
  print_words((uint32_t *) ptxt, 4);
  gift128f_enc_c99(ctxt, ptxt, rkey);  // encryption in C
  print_words((uint32_t *) ctxt, 4);

#if defined(GIFTCOFB_ASSEMBLER)
  printf("Test 1 - ASM implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = 0;
  print_words((uint32_t *) ptxt, 4);
  gift128f_enc_asm(ctxt, ptxt, rkey);  // encryption in ASM
  print_words((uint32_t *) ctxt, 4);
#endif

  // 2nd test: plaintext is initialized with byte-indeces

  printf("Test 2 - C99 implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = (uint8_t) i;
  print_words((uint32_t *) ptxt, 4);
  gift128f_enc_c99(ctxt, ptxt, rkey);  // encryption in C
  print_words((uint32_t *) ctxt, 4);

#if defined(GIFTCOFB_ASSEMBLER)
  printf("Test 2 - ASM implementation:\n");
  for (i = 0; i < 16; i++) ptxt[i] = (uint8_t)i;
  print_words((uint32_t *) ptxt, 4);
  gift128f_enc_asm(ctxt, ptxt, rkey);  // encryption in ASM
  print_words((uint32_t *) ctxt, 4);
#endif

  // Expected result for 40 rounds
  // -----------------------------
  // Test 1 - C99 implementation:
  // 00000000 00000000 00000000 00000000
  // 0f87e4fb 0359d851 34a741fd a52b2c68
  // Test 1 - ASM implementation:
  // 00000000 00000000 00000000 00000000
  // 0f87e4fb 0359d851 34a741fd a52b2c68
  // Test 2 - C99 implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c
  // 6ecc9848 c6c75cf0 17fbfb70 092b90e9
  // Test 2 - ASM implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c
  // 6ecc9848 c6c75cf0 17fbfb70 092b90e9
}
