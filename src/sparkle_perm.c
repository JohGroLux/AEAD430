///////////////////////////////////////////////////////////////////////////////
// sparkle_perm.c: Optimized C99 implementation of the SPARKLE permutation.  //
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


#define MAX_BRANCHES 8

#define ROR(x, n) (((x) >> (n)) | ((x) << (32-(n))))
// #define ELL(x) (ROR((x), 16) ^ ((x) & 0xFFFFU))
#define ELL(x) (ROR(((x) ^ ((x) << 16)), 16))


// Round constants
static const uint32_t RCON[MAX_BRANCHES] = {      \
  0xB7E15162, 0xBF715880, 0x38B4DA56, 0x324E7738, \
  0xBB1185EB, 0x4F7C7B57, 0xCFBFA1C8, 0xC2B3293D  \
};


#if (defined(__AVR) || defined(__AVR__))
extern void sparkle_avr(uint32_t *state, int brans, int steps);
#define sparkle_asm(state, brans, steps) sparkle_avr((state), (brans), (steps))
#define SPARKLE_ASSEMBLER
#endif

#if (defined(__MSP430__) || defined(__ICC430__))
extern void sparkle_msp(uint32_t *state, int brans, int steps);
#define sparkle_asm(state, brans, steps) sparkle_msp((state), (brans), (steps))
#define SPARKLE_ASSEMBLER
#endif


// The 1st version of the SPARKLE permutation is based on the source code in
// `sparkle.c` of the `opt` implementation from the designers.

void sparkle_c99_V1(uint32_t *state, int brans, int steps)
{
  int i, j;  // Step and branch counter
  uint32_t rc, tx, ty, x0, y0;
  
  for(i = 0; i < steps; i++) {
    // Add round constant
    state[1] ^= RCON[i%MAX_BRANCHES];
    state[3] ^= i;
    // ARXBOX layer
    for(j = 0; j < 2*brans; j += 2) {
      rc = RCON[j>>1];
      state[j] += ROR(state[j+1], 31);
      state[j+1] ^= ROR(state[j], 24);
      state[j] ^= rc;
      state[j] += ROR(state[j+1], 17);
      state[j+1] ^= ROR(state[j], 17);
      state[j] ^= rc;
      state[j] += state[j+1];
      state[j+1] ^= ROR(state[j], 31);
      state[j] ^= rc;
      state[j] += ROR(state[j+1], 24);
      state[j+1] ^= ROR(state[j], 16);
      state[j] ^= rc;
    }
    // Linear layer
    tx = x0 = state[0];
    ty = y0 = state[1];
    for(j = 2; j < brans; j += 2) {
      tx ^= state[j];
      ty ^= state[j+1];
    }
    tx = ELL(tx);
    ty = ELL(ty);
    for (j = 2; j < brans; j += 2) {
      state[j-2] = state[j+brans] ^ state[j] ^ ty;
      state[j+brans] = state[j];
      state[j-1] = state[j+brans+1] ^ state[j+1] ^ tx;
      state[j+brans+1] = state[j+1];
    }
    state[brans-2] = state[brans] ^ x0 ^ ty;
    state[brans] = x0;
    state[brans-1] = state[brans+1] ^ y0 ^ tx;
    state[brans+1] = y0;
  }
}


// The 2nd version of the SPARKLE permutation is similar to the 1st version
// above, but performs that computation of `tx` and `ty` in the ARXbox-layer
// instead of the linear layer.

void sparkle_c99_V2(uint32_t *state, int brans, int steps)
{
  int i, j;  // Step and branch counter
  uint32_t rc, tx, ty, x0, y0;

  for (i = 0; i < steps; i++) {
    // Add round constant
    state[1] ^= RCON[i%MAX_BRANCHES];
    state[3] ^= i;
    // ARXBOX layer
    tx = ty = 0;
    for (j = 0; j < brans; j += 2) {
      rc = RCON[j >> 1];
      state[j] += ROR(state[j+1], 31);
      state[j+1] ^= ROR(state[j], 24);
      state[j] ^= rc;
      state[j] += ROR(state[j+1], 17);
      state[j+1] ^= ROR(state[j], 17);
      state[j] ^= rc;
      state[j] += state[j+1];
      state[j+1] ^= ROR(state[j], 31);
      state[j] ^= rc;
      state[j] += ROR(state[j+1], 24);
      state[j+1] ^= ROR(state[j], 16);
      state[j] ^= rc;
      tx ^= state[j];
      ty ^= state[j+1];
    }
    for (j = brans; j < 2*brans; j += 2) {
      rc = RCON[j >> 1];
      state[j] += ROR(state[j+1], 31);
      state[j+1] ^= ROR(state[j], 24);
      state[j] ^= rc;
      state[j] += ROR(state[j+1], 17);
      state[j+1] ^= ROR(state[j], 17);
      state[j] ^= rc;
      state[j] += state[j + 1];
      state[j+1] ^= ROR(state[j], 31);
      state[j] ^= rc;
      state[j] += ROR(state[j+1], 24);
      state[j+1] ^= ROR(state[j], 16);
      state[j] ^= rc;
    }
    // Linear layer
    tx = ELL(tx);
    ty = ELL(ty);
    x0 = state[0];
    y0 = state[1];
    for (j = 2; j < brans; j += 2) {
      state[j-2] = state[j+brans] ^ state[j] ^ ty;
      state[j+brans] = state[j];
      state[j-1] = state[j+brans+1] ^ state[j+1] ^ tx;
      state[j+brans+1] = state[j+1];
    }
    state[brans-2] = state[brans] ^ x0 ^ ty;
    state[brans] = x0;
    state[brans-1] = state[brans+1] ^ y0 ^ tx;
    state[brans+1] = y0;
  }
}


// Print the $2*brans$ state-words of SPARKLE in Hex format.

static void print_state(const uint32_t *state, int brans)
{
  UChar buffer[18*MAX_BRANCHES], byte;
  int i, j, k = 0;

  // for (i = 0; i < 2*brans; i++) {
  //   printf("%08x ", state[i]);
  // }
  // printf("\n");

  for (i = 0; i < 2*brans; i++) {
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


/*
// Print a byte-array in Hex format (the output is limited to the first 64
// bytes of the byte-array).

static void print_bytes(const char* str, const UChar *bytearray, size_t len)
{
  UChar buffer[148], byte;
  size_t i, j, slen = 0;

  if (str != NULL) {
    slen = MIN(16, strlen(str));
    memcpy(buffer, str, slen);
  }

  j = slen;
  for (i = 0; i < MIN(64, len); i++) {
    byte = bytearray[i] >> 4;
    // replace 87 by 55 to get uppercase letters
    buffer[j++] = byte + ((byte < 10) ? 48 : 87);
    byte = bytearray[i] & 0xf;
    buffer[j++] = byte + ((byte < 10) ? 48 : 87);
  }
  if (len > 64) {
    buffer[j] = buffer[j+1] = buffer[j+2] = '.';
    j += 3;
  }
  buffer[j] = '\0';

  printf("%s\n", buffer);
}
*/


// Simple test function for the SPARKLE permutation.

void test_sparkle(int brans, int steps)
{
  uint32_t state[2*MAX_BRANCHES];
  int i;

  // 1st test: state is initialized with all-0 words

  printf("Test 1 - C99 implementation:\n");
  for (i = 0; i < 2*brans; i++) state[i] = 0;
  print_state(state, brans);
  sparkle_c99_V2(state, brans, steps);  // permutation in C
  print_state(state, brans);

#if defined(SPARKLE_ASSEMBLER)
  printf("Test 1 - ASM implementation:\n");
  for (i = 0; i < 2*brans; i++) state[i] = 0;
  print_state(state, brans);
  sparkle_asm(state, brans, steps);  // permutation in ASM
  print_state(state, brans);
#endif

  // 2nd test: state is initialized with byte-indeces

  printf("Test 2 - C99 implementation:\n");
  for (i = 0; i < 8*brans; i++) ((uint8_t *) state)[i] = (uint8_t) i;
  print_state(state, brans);
  sparkle_c99_V2(state, brans, steps);  // permutation in C
  print_state(state, brans);

#if defined(SPARKLE_ASSEMBLER)
  printf("Test 2 - ASM implementation:\n");
  for (i = 0; i < 8*brans; i++) ((uint8_t *) state)[i] = (uint8_t) i;
  print_state(state, brans);
  sparkle_asm(state, brans, steps);  // permutation in ASM
  print_state(state, brans);
#endif

  // Expected result for 6 branches and 7 steps
  // ------------------------------------------
  // Test 1 - C99 implementation:
  // 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
  // 4df96879 8c7c2c33 82236b4a 904f4dd7 d6a030e8 f03b09aa c4c3bb34 f063dff9 61f9ceff 8ec21ffa 93df370f 83acf1e2
  // Test 1 - ASM implementation:
  // 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000
  // 4df96879 8c7c2c33 82236b4a 904f4dd7 d6a030e8 f03b09aa c4c3bb34 f063dff9 61f9ceff 8ec21ffa 93df370f 83acf1e2
  // Test 2 - C99 implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c 13121110 17161514 1b1a1918 1f1e1d1c 23222120 27262524 2b2a2928 2f2e2d2c
  // fd68bebb f1e79844 52592dce 1292b346 4ffbd73c 15e46b29 69fe733a 267f53c6 325a0903 2d5c63ed f6a4bd58 048223a1
  // Test 2 - ASM implementation:
  // 03020100 07060504 0b0a0908 0f0e0d0c 13121110 17161514 1b1a1918 1f1e1d1c 23222120 27262524 2b2a2928 2f2e2d2c
  // fd68bebb f1e79844 52592dce 1292b346 4ffbd73c 15e46b29 69fe733a 267f53c6 325a0903 2d5c63ed f6a4bd58 048223a1
}
