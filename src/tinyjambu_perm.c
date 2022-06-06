///////////////////////////////////////////////////////////////////////////////
// tinyjambu_perm.c: Opt C99 implementation of the TinyJambu permutation.    //
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


typedef unsigned char UChar;
typedef unsigned long long int ULLInt;


// rounds for processing of associated data
#define NROUND1 128*5
// rounds for encryption (resp. decryption)
#define NROUND2 128*8


#if (defined(__AVR) || defined(__AVR__))
extern void state_update_avr(uint32_t *state, const UChar *key, int steps);
#define state_update_asm(state, key, steps) \
  state_update_avr((state), (key), (steps))
#define TINYJAMBU_ASSEMBLER
#endif

#if (defined(__MSP430__) || defined(__ICC430__))
extern void state_update_msp(uint32_t *state, const UChar *key, int steps);
#define state_update_asm(state, key, steps) \
  state_update_msp((state), (key), (steps))
#define TINYJAMBU_ASSEMBLER
#endif


// The 1st version of the TinyJambu state-update function is based on the
// source code in `encrypt.c` of the `opt` implementation from the designers.

void state_update_c99_V1(uint32_t *state, const UChar *key, int steps)
{
  const uint32_t *key32 = (const void *) key;
  uint32_t t0, t1, t2, t3;
  int i;

  // in each iteration, we compute 128 rounds of the state update function.
  for (i = 0; i < steps; i += 128) {
    t0 = (state[1] >> 15) | (state[2] << 17);  // 47 = 1*32+15
    t1 = (state[2] >>  6) | (state[3] << 26);  // 47+23 = 70 = 2*32+6
    t2 = (state[2] >> 21) | (state[3] << 11);  // 47+23+15 = 85 = 2*32+21
    t3 = (state[2] >> 27) | (state[3] <<  5);  // 47+23+15+6 = 91 = 2*32+27
    state[0] ^= t0 ^ (~(t1 & t2)) ^ t3 ^ key32[0];

    t0 = (state[2] >> 15) | (state[3] << 17);
    t1 = (state[3] >>  6) | (state[0] << 26);
    t2 = (state[3] >> 21) | (state[0] << 11);
    t3 = (state[3] >> 27) | (state[0] <<  5);
    state[1] ^= t0 ^ (~(t1 & t2)) ^ t3 ^ key32[1];

    t0 = (state[3] >> 15) | (state[0] << 17);
    t1 = (state[0] >>  6) | (state[1] << 26);
    t2 = (state[0] >> 21) | (state[1] << 11);
    t3 = (state[0] >> 27) | (state[1] <<  5);
    state[2] ^= t0 ^ (~(t1 & t2)) ^ t3 ^ key32[2];

    t0 = (state[0] >> 15) | (state[1] << 17);
    t1 = (state[1] >>  6) | (state[2] << 26);
    t2 = (state[1] >> 21) | (state[2] << 11);
    t3 = (state[1] >> 27) | (state[2] <<  5);
    state[3] ^= t0 ^ (~(t1 & t2)) ^ t3 ^ key32[3];
  }
}


// The 2nd version of the TinyJambu state-update function is similar to the
// 1st version except that the four state-words are not updated word-wise but
// in 16-bit slices.

void state_update_c99_V2(uint32_t *state, const UChar *key, int steps)
{
  uint16_t *state16 = (uint16_t *) state;
  const uint16_t *key16 = (const void *) key;
  // half (i.e. 16-bit) of t0, t1, t2, t3
  uint16_t ht0, ht1, ht2, ht3;
  int i;

  for (i = steps; i > 0; i -= 128) {
    // update of lower half of 32-bit word state[0]
    ht0 = (state16[2] >> 15) | (state16[3] <<  1);
    ht3 = (state16[5] >> 11) | (state16[6] <<  5);
    state16[0] ^= (ht0 ^ ht3);
    ht1 = (state16[4] >>  6) | (state16[5] << 10);
    ht2 = (state16[5] >>  5) | (state16[6] << 11);
    state16[0] ^= (~(ht1 & ht2));
    state16[0] ^= key16[0];

    // update of higher half of 32-bit word state[0]
    ht0 = (state16[3] >> 15) | (state16[4] <<  1);
    ht3 = (state16[6] >> 11) | (state16[7] <<  5);
    state16[1] ^= (ht0 ^ ht3);
    ht1 = (state16[5] >>  6) | (state16[6] << 10);
    ht2 = (state16[6] >>  5) | (state16[7] << 11);
    state16[1] ^= (~(ht1 & ht2));
    state16[1] ^= key16[1];

    // update of lower half of 32-bit word state[1]
    ht0 = (state16[4] >> 15) | (state16[5] <<  1);
    ht3 = (state16[7] >> 11) | (state16[0] <<  5);
    state16[2] ^= (ht0 ^ ht3);
    ht1 = (state16[6] >>  6) | (state16[7] << 10);
    ht2 = (state16[7] >>  5) | (state16[0] << 11);
    state16[2] ^= (~(ht1 & ht2));
    state16[2] ^= key16[2];

    // update of higher half of 32-bit word state[1]
    ht0 = (state16[5] >> 15) | (state16[6] <<  1);
    ht3 = (state16[0] >> 11) | (state16[1] <<  5);
    state16[3] ^= (ht0 ^ ht3);
    ht1 = (state16[7] >>  6) | (state16[0] << 10);
    ht2 = (state16[0] >>  5) | (state16[1] << 11);
    state16[3] ^= (~(ht1 & ht2));
    state16[3] ^= key16[3];

    // update of lower half of 32-bit word state[2]
    ht0 = (state16[6] >> 15) | (state16[7] <<  1);
    ht3 = (state16[1] >> 11) | (state16[2] <<  5);
    state16[4] ^= (ht0 ^ ht3);
    ht1 = (state16[0] >>  6) | (state16[1] << 10);
    ht2 = (state16[1] >>  5) | (state16[2] << 11);
    state16[4] ^= (~(ht1 & ht2));
    state16[4] ^= key16[4];

    // update of higher half of 32-bit word state[2]
    ht0 = (state16[7] >> 15) | (state16[0] <<  1);
    ht3 = (state16[2] >> 11) | (state16[3] <<  5);
    state16[5] ^= (ht0 ^ ht3);
    ht1 = (state16[1] >>  6) | (state16[2] << 10);
    ht2 = (state16[2] >>  5) | (state16[3] << 11);
    state16[5] ^= (~(ht1 & ht2));
    state16[5] ^= key16[5];

    // update of lower half of 32-bit word state[3]
    ht0 = (state16[0] >> 15) | (state16[1] <<  1);
    ht3 = (state16[3] >> 11) | (state16[4] <<  5);
    state16[6] ^= (ht0 ^ ht3);
    ht1 = (state16[2] >>  6) | (state16[3] << 10);
    ht2 = (state16[3] >>  5) | (state16[4] << 11);
    state16[6] ^= (~(ht1 & ht2));
    state16[6] ^= key16[6];

    // update of higher half of 32-bit word state[3]
    ht0 = (state16[1] >> 15) | (state16[2] <<  1);
    ht3 = (state16[4] >> 11) | (state16[5] <<  5);
    state16[7] ^= (ht0 ^ ht3);
    ht1 = (state16[3] >>  6) | (state16[4] << 10);
    ht2 = (state16[4] >>  5) | (state16[5] << 11);
    state16[7] ^= (~(ht1 & ht2));
    state16[7] ^= key16[7];
  }
}


// Print the 4 state-words of TinyJambu in Hex format.

static void print_state(const uint32_t *state)
{
  UChar buffer[36], byte;
  int i, j, k = 0;

  // for (i = 0; i < 4; i++) {
  //   printf("%08x ", state[i]);
  // }
  // printf("\n");

  for (i = 0; i < 4; i++) {
    for (j = 7; j >= 0; j--) {
      byte = (state[i] >> 4*j) & 0xf;
      // replace 87 by 55 to get uppercase letters
      buffer[k++] = byte + ((byte < 10) ? 48 : 87);
    }
    buffer[k++] = ' ';
  }
  buffer[k-1] = '\0';

  printf("%s\n", buffer);
}


// Simple test function for the TinyJambu permutation.

void test_tinyjambu(int steps)
{
  uint32_t state[4];
  UChar key[16];
  int i;

  for (i = 0; i < 16; i++) key[i] = (UChar) 128 + i;

  // 1st test: state is initialized with all-0 words

  printf("Test 1 - C99 implementation:\n");
  for (i = 0; i < 4; i++) state[i] = 0;
  print_state(state);
  state_update_c99_V2(state, key, steps);  // permutation in C
  print_state(state);

#if defined(TINYJAMBU_ASSEMBLER)
  printf("Test 1 - ASM implementation:\n");
  for (i = 0; i < 4; i++) state[i] = 0;
  print_state(state);
  state_update_asm(state, key, steps);  // permutation in ASM
  print_state(state);
#endif

  // 2nd test: state is initialized with byte-indeces

  printf("Test 2 - C99 implementation:\n");
  for (i = 0; i < 16; i++) ((uint8_t *) state)[i] = (uint8_t) i;
  print_state(state);
  state_update_c99_V2(state, key, steps);  // permutation in C
  print_state(state);

#if defined(TINYJAMBU_ASSEMBLER)
  printf("Test 2 - ASM implementation:\n");
  for (i = 0; i < 16; i++) ((uint8_t *) state)[i] = (uint8_t) i;
  print_state(state);
  state_update_asm(state, key, steps);  // permutation in ASM
  print_state(state);
#endif

  // Expected result for 1024 steps
  // ------------------------------
  // Test 1 - C99 implementation:
  // 00000000 00000000 00000000 00000000
  // 81923776 dd2d7f96 3ef05327 c5a00770
  // Test 1 - ASM implementation:
  // 00000000 00000000 00000000 00000000
  // 81923776 dd2d7f96 3ef05327 c5a00770
  // Test 2 - C99 implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c
  // 80c7c53b 23b209b3 e80895c9 efceda8c
  // Test 2 - ASM implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c
  // 80c7c53b 23b209b3 e80895c9 efceda8c
}
