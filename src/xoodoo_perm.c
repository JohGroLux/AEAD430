///////////////////////////////////////////////////////////////////////////////
// xoodoo_perm.c: C99 implementation and unit-test of Xoodoo permutation.    //
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


typedef uint32_t tXoodooLane;
typedef unsigned char UChar;
typedef unsigned long long int ULLInt;


#define MAXROUNDS 12
#define NROWS 3
#define NCOLUMNS 4
#define NLANES (NCOLUMNS * NROWS)

// rotation and index macro
#define ROL32(a, b) ((((uint32_t) a) << (b)) ^ (((uint32_t) a) >> (32 - (b))))
#define IDX(x, y) ((((y) % NROWS) * NCOLUMNS) + ((x) % NCOLUMNS))

// min/max macros
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))


#if (defined(__AVR) || defined(__AVR__))
extern void xoodoo_avr(uint32_t *state, int rounds);
#define xoodoo_asm(state, rounds) xoodoo_avr((state), (rounds))
#define XOODOO_ASSEMBLER
#endif

#if (defined(__MSP430__) || defined(__ICC430__))
extern void xoodoo_msp(uint32_t *state, int rounds);
#define xoodoo_asm(state, rounds) xoodoo_msp((state), (rounds))
#define XOODOO_ASSEMBLER
#endif


static const uint32_t RC[MAXROUNDS] = {           \
  0x00000058, 0x00000038, 0x000003C0, 0x000000D0, \
  0x00000120, 0x00000014, 0x00000060, 0x0000002C, \
  0x00000380, 0x000000F0, 0x000001A0, 0x00000012  \
};


// The 1st version of the Xoodoo permutation is based on the source code in
// `Xoodoo-reference.c` (function `Xoodoo_Round` and `Xoodoo_Permute_Nrounds`)
// of the `ref` implementation from the designers (see XKCP on GitHub in the
// directory `lib/low/Xoodoo`).

void xoodoo_c99(tXoodooLane *a, int nr)
{
  tXoodooLane b[NLANES], p[NCOLUMNS], e[NCOLUMNS];
  unsigned int x, y;  // do not change type to int!
  int i;

  for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i) {

    // Theta: column parity mixer
    for (x = 0; x < NCOLUMNS; ++x) {
      p[x] = a[IDX(x, 0)] ^ a[IDX(x, 1)] ^ a[IDX(x, 2)];
    }
    for (x = 0; x < NCOLUMNS; ++x) {
      e[x] = ROL32(p[(x-1)%4], 5) ^ ROL32(p[(x-1)%4], 14);
    }
    for (x = 0; x < NCOLUMNS; ++x) {
      for (y = 0; y < NROWS; ++y) {
        a[IDX(x, y)] ^= e[x];
      }
    }

    // Rho-west: plane shift (rotation)
    for (x = 0; x < NCOLUMNS; ++x) {
      b[IDX(x, 0)] = a[IDX(x, 0)];
      b[IDX(x, 1)] = a[IDX(x - 1, 1)];
      b[IDX(x, 2)] = ROL32(a[IDX(x, 2)], 11);
    }
    memcpy(a, b, sizeof(b));

    // Iota: addition of round constant
    a[0] ^= RC[i];

    // Chi: non-linear layer (vertically)
    for (x = 0; x < NCOLUMNS; ++x) {
      for (y = 0; y < NROWS; ++y) {
        b[IDX(x, y)] = a[IDX(x, y)] ^ (~a[IDX(x, y + 1)] & a[IDX(x, y + 2)]);
      }
    }
    memcpy(a, b, sizeof(b));

    // Rho-east: plane shift (rotation)
    for (x = 0; x < NCOLUMNS; ++x) {
      b[IDX(x, 0)] = a[IDX(x, 0)];
      b[IDX(x, 1)] = ROL32(a[IDX(x, 1)], 1);
      b[IDX(x, 2)] = ROL32(a[IDX(x + 2, 2)], 8);
    }
    memcpy(a, b, sizeof(b));
  }
}


// The 2nd version of the Xoodoo permutation is similar to the 1st version
// above, but all loops inside the round function are unrolled.

void xoodoo_c99_V2(tXoodooLane *a, int nr)
{
  tXoodooLane b[NLANES], p[NCOLUMNS], e[NCOLUMNS];
  int i;

  for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i) {

    // Theta: column parity mixer
    p[0] = a[0] ^ a[4] ^ a[8];
    p[1] = a[1] ^ a[5] ^ a[9];
    p[2] = a[2] ^ a[6] ^ a[10];
    p[3] = a[3] ^ a[7] ^ a[11];
    e[0] = ROL32(p[3], 5) ^ ROL32(p[3], 14);
    e[1] = ROL32(p[0], 5) ^ ROL32(p[0], 14);
    e[2] = ROL32(p[1], 5) ^ ROL32(p[1], 14);
    e[3] = ROL32(p[2], 5) ^ ROL32(p[2], 14);
    a[0] ^= e[0];
    a[4] ^= e[0];
    a[8] ^= e[0];
    a[1] ^= e[1];
    a[5] ^= e[1];
    a[9] ^= e[1];
    a[2] ^= e[2];
    a[6] ^= e[2];
    a[10] ^= e[2];
    a[3] ^= e[3];
    a[7] ^= e[3];
    a[11] ^= e[3];

    // Rho-west: plane shift (rotation)
    b[0] = a[0];
    b[4] = a[7];
    b[8] = ROL32(a[8], 11);
    b[1] = a[1];
    b[5] = a[4];
    b[9] = ROL32(a[9], 11);
    b[2] = a[2];
    b[6] = a[5];
    b[10] = ROL32(a[10], 11);
    b[3] = a[3];
    b[7] = a[6];
    b[11] = ROL32(a[11], 11);
    memcpy(a, b, sizeof(b));

    // Iota: addition of round constant
    a[0] ^= RC[i];

    // Chi: non-linear layer (vertically)
    b[0] = a[0] ^ (~a[4] & a[8]);    // x = 0, y = 0
    b[4] = a[4] ^ (~a[8] & a[0]);    // x = 0, y = 1
    b[8] = a[8] ^ (~a[0] & a[4]);    // x = 0, y = 2
    b[1] = a[1] ^ (~a[5] & a[9]);    // x = 1, y = 0
    b[5] = a[5] ^ (~a[9] & a[1]);    // x = 1, y = 1
    b[9] = a[9] ^ (~a[1] & a[5]);    // x = 1, y = 2
    b[2] = a[2] ^ (~a[6] & a[10]);   // x = 2, y = 0
    b[6] = a[6] ^ (~a[10] & a[2]);   // x = 2, y = 1
    b[10] = a[10] ^ (~a[2] & a[6]);  // x = 2, y = 2
    b[3] = a[3] ^ (~a[7] & a[11]);   // x = 3, y = 0
    b[7] = a[7] ^ (~a[11] & a[3]);   // x = 3, y = 1
    b[11] = a[11] ^ (~a[3] & a[7]);  // x = 3, y = 2
    memcpy(a, b, sizeof(b));

    // Rho-east: plane shift (rotation)
    b[0] = a[0];
    b[4] = ROL32(a[4], 1);
    b[8] = ROL32(a[10], 8);
    b[1] = a[1];
    b[5] = ROL32(a[5], 1);
    b[9] = ROL32(a[11], 8);
    b[2] = a[2];
    b[6] = ROL32(a[6], 1);
    b[10] = ROL32(a[8], 8);
    b[3] = a[3];
    b[7] = ROL32(a[7], 1);
    b[11] = ROL32(a[9], 8);
    memcpy(a, b, sizeof(b));
  }
}


// The third version of the Xoodoo permutation is also unrolled like the 2nd
// version above, but integrates parts of Rho-west into Theta and parts of
// Rho-east into Chi, repsectively, with the goal of reducing the number of
// memory accesses.

void xoodoo_c99_V3(tXoodooLane *a, int nr)
{
  tXoodooLane p[NCOLUMNS], e[NCOLUMNS];
  int i;

  for (i = MAXROUNDS - nr; i < MAXROUNDS; ++i) {

    // Theta and a part of Rho-west
    p[0] = a[0] ^ a[4] ^ a[8];
    p[1] = a[1] ^ a[5] ^ a[9];
    p[2] = a[2] ^ a[6] ^ a[10];
    p[3] = a[3] ^ a[7] ^ a[11];
    e[0] = ROL32(p[3], 5) ^ ROL32(p[3], 14);
    e[1] = ROL32(p[0], 5) ^ ROL32(p[0], 14);
    e[2] = ROL32(p[1], 5) ^ ROL32(p[1], 14);
    e[3] = ROL32(p[2], 5) ^ ROL32(p[2], 14);
    a[0] = a[0] ^ e[0];
    a[4] = a[4] ^ e[0];
    a[8] = ROL32((a[8] ^ e[0]), 11);
    a[1] = a[1] ^ e[1];
    a[5] = a[5] ^ e[1];
    a[9] = ROL32((a[9] ^ e[1]), 11);
    a[2] = a[2] ^ e[2];
    a[6] = a[6] ^ e[2];
    a[10] = ROL32((a[10] ^ e[2]), 11);
    a[3] = a[3] ^ e[3];
    a[7] = a[7] ^ e[3];
    a[11] = ROL32((a[11] ^ e[3]), 11);

    // Remaining part of Rho-west
    p[0] = a[4];
    p[1] = a[5];
    p[2] = a[6];
    p[3] = a[7];
    a[4] = p[3];
    a[5] = p[0];
    a[6] = p[1];
    a[7] = p[2];
 
    // Iota: addition of round constant
    a[0] ^= RC[i];

    // Chi and a part of Rho-east
    p[0] = a[4] ^ (~a[8] & a[0]);
    e[0] = a[8] ^ (~a[0] & a[4]);
    a[0] = a[0] ^ (~a[4] & a[8]);
    a[4] = ROL32(p[0], 1);
    a[8] = ROL32(e[0], 8);
    p[1] = a[5] ^ (~a[9] & a[1]);
    e[1] = a[9] ^ (~a[1] & a[5]);
    a[1] = a[1] ^ (~a[5] & a[9]);
    a[5] = ROL32(p[1], 1);
    a[9] = ROL32(e[1], 8);
    p[2] = a[6] ^ (~a[10] & a[2]); 
    e[2] = a[10] ^ (~a[2] & a[6]);
    a[2] = a[2] ^ (~a[6] & a[10]);
    a[6] = ROL32(p[2], 1);
    a[10] = ROL32(e[2], 8);
    p[3] = a[7] ^ (~a[11] & a[3]);
    e[3] = a[11] ^ (~a[3] & a[7]);
    a[3] = a[3] ^ (~a[7] & a[11]);
    a[7] = ROL32(p[3], 1);
    a[11] = ROL32(e[3], 8);

    // Remaining part of Rho-east
    p[0] = a[8];
    p[1] = a[9];
    p[2] = a[10];
    p[3] = a[11];
    a[8] = p[2];
    a[9] = p[3];
    a[10] = p[0];
    a[11] = p[1];
  }
}


// Print the 12 state-words of Xoodoo in Hex format

static void print_state(const tXoodooLane *a)
{
  UChar buffer[15*NLANES-NROWS], byte;
  int i, j, k, l = 0;

  // printf("a00: %08lx, a01: %08lx, a02: %08lx, a03: %08lx\n", \
  //   a[0+0], a[0+1], a[0+2], a[0+3]);
  // printf("a10: %08lx, a11: %08lx, a12: %08lx, a13: %08lx\n", \
  //   a[4+0], a[4+1], a[4+2], a[4+3]);
  // printf("a20: %08lx, a21: %08lx, a22: %08lx, a23: %08lx\n", \
  //   a[8+0], a[8+1], a[8+2], a[8+3]);

  for (i = 0; i < NROWS; i++) {
    for (j = 0; j < NCOLUMNS; j++) {
      buffer[l++] = 'a';
      buffer[l++] = i + 48;
      buffer[l++] = j + 48;
      buffer[l++] = ':';
      buffer[l++] = ' ';
      for (k = 7; k >= 0; k--) {
        byte = (a[4*i+j] >> 4*k) & 0xf;
        // replace 87 by 55 to get uppercase letters
        buffer[l++] = byte + ((byte < 10) ? 48 : 87);
      }
      if (j < NCOLUMNS - 1) {
        buffer[l++] = ',';
        buffer[l++] = ' ';
      }
    }
    buffer[l++] = '\n';
  }
  buffer[l-1] = '\0';

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


// Simple test function for the Xoodoo permutation.

void xoodoo_test_perm(int rounds)
{
  tXoodooLane state[NLANES];
  int i;

  // 1st test: state is initialized with all-0 words

  printf("Test 1 - C99 implementation:\n");
  for (i = 0; i < NLANES; i++) state[i] = 0;
  print_state(state);
  xoodoo_c99(state, rounds);  // permutation in C
  print_state(state);

#if defined(XOODOO_ASSEMBLER)
  printf("Test 1 - ASM implementation:\n");
  for (i = 0; i < NLANES; i++) state[i] = 0;
  print_state(state);
  xoodoo_asm(state, rounds);  // permutation in ASM
  print_state(state);
#endif

  // 2nd test: state is initialized with byte-indeces

  printf("Test 2 - C99 implementation:\n");
  for (i = 0; i < 4*NLANES; i++) ((uint8_t *) state)[i] = (uint8_t) i;
  print_state(state);
  xoodoo_c99(state, rounds);  // permutation in C
  print_state(state);

#if defined(XOODOO_ASSEMBLER)
  printf("Test 2 - ASM implementation:\n");
  for (i = 0; i < 4*NLANES; i++) ((uint8_t *) state)[i] = (uint8_t) i;
  print_state(state);
  xoodoo_asm(state, rounds);  // permutation in ASM
  print_state(state);
#endif

  // Expected result for 12 rounds
  // -----------------------------
  // Test 1 - C99 implementation:
  // a00: 00000000, a01: 00000000, a02: 00000000, a03: 00000000
  // a10: 00000000, a11: 00000000, a12: 00000000, a13: 00000000
  // a20: 00000000, a21: 00000000, a22: 00000000, a23: 00000000
  // a00: 89d5d88d, a01: a963fcbf, a02: 1b232d19, a03: ffa5a014
  // a10: 36b18106, a11: afc7c1fe, a12: aee57cbe, a13: a77540bd
  // a20: 2e86e870, a21: fef5b7c9, a22: 8b4fadf2, a23: 5e4f4062
  // Test 1 - ASM implementation:
  // a00: 00000000, a01: 00000000, a02: 00000000, a03: 00000000
  // a10: 00000000, a11: 00000000, a12: 00000000, a13: 00000000
  // a20: 00000000, a21: 00000000, a22: 00000000, a23: 00000000
  // a00: 89d5d88d, a01: a963fcbf, a02: 1b232d19, a03: ffa5a014
  // a10: 36b18106, a11: afc7c1fe, a12: aee57cbe, a13: a77540bd
  // a20: 2e86e870, a21: fef5b7c9, a22: 8b4fadf2, a23: 5e4f4062
  // Test 2 - C99 implementation:
  // a00: 03020100, a01: 07060504, a02: 0b0a0908, a03: 0f0e0d0c
  // a10: 13121110, a11: 17161514, a12: 1b1a1918, a13: 1f1e1d1c
  // a20: 23222120, a21: 27262524, a22: 2b2a2928, a23: 2f2e2d2c
  // a00: b5ae3376, a01: 60bfcc5d, a02: d7dfa6d4, a03: bf066d50
  // a10: ae97acb2, a11: d38a0d97, a12: 7b118513, a13: 41a775b7
  // a20: 0b54b1b3, a21: 6fe93bb5, a22: af8f2b3b, a23: b6a376a6
  // Test 2 - ASM implementation:
  // a00: 03020100, a01: 07060504, a02: 0b0a0908, a03: 0f0e0d0c
  // a10: 13121110, a11: 17161514, a12: 1b1a1918, a13: 1f1e1d1c
  // a20: 23222120, a21: 27262524, a22: 2b2a2928, a23: 2f2e2d2c
  // a00: b5ae3376, a01: 60bfcc5d, a02: d7dfa6d4, a03: bf066d50
  // a10: ae97acb2, a11: d38a0d97, a12: 7b118513, a13: 41a775b7
  // a20: 0b54b1b3, a21: 6fe93bb5, a22: af8f2b3b, a23: b6a376a6
}
