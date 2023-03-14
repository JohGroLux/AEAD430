///////////////////////////////////////////////////////////////////////////////
// isap_perm.c: C99 implementation and unit-test of ASCON128 permutation.    //
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

typedef union {
  uint64_t x[5];
  uint32_t w[5][2];
  uint8_t b[5][8];
} State;


// rotation macro
#define ROR64(x, d) (((x) >> (d)) | ((x) << (64 - (d))))

// min/max macros
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

// round constants
#define START(n) (((n << 4) - n) + END)
#define DEC 0x0f
#define END 0x3c


#if (defined(__AVR) || defined(__AVR__))
extern void isap_avr(State *s, int nr);
#define isap_asm(s, nr) isap_avr((s), (nr))
#define ISAP_ASSEMBLER
#endif

#if (defined(__MSP430__) || defined(__ICC430__))
extern void isap_msp(State *s, int nr);
#define isap_asm(s, nr) isap_msp((s), (nr))
#define ISAP_ASSEMBLER
#endif


// The 1st version of the ASCON128v12 permutation is based on the source code
// in `round.h` of the `ref` implementation from the designers.

void isap_c99(State *s, int nr)
{
  State t;
  int rc;

  for (rc = START(nr); rc > END; rc -= DEC) {
    // addition of round constant
    s->x[2] ^= (uint64_t) rc;
    // substitution layer
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    // start of keccak s-box
    t.x[0] = s->x[0] ^ (~s->x[1] & s->x[2]);
    t.x[1] = s->x[1] ^ (~s->x[2] & s->x[3]);
    t.x[2] = s->x[2] ^ (~s->x[3] & s->x[4]);
    t.x[3] = s->x[3] ^ (~s->x[4] & s->x[0]);
    t.x[4] = s->x[4] ^ (~s->x[0] & s->x[1]);
    // end of keccak s-box
    t.x[1] ^= t.x[0];
    t.x[0] ^= t.x[4];
    t.x[3] ^= t.x[2];
    t.x[2] = ~t.x[2];
    // linear diffusion layer
    s->x[0] = t.x[0] ^ ROR64(t.x[0], 19) ^ ROR64(t.x[0], 28);
    s->x[1] = t.x[1] ^ ROR64(t.x[1], 61) ^ ROR64(t.x[1], 39);
    s->x[2] = t.x[2] ^ ROR64(t.x[2],  1) ^ ROR64(t.x[2],  6);
    s->x[3] = t.x[3] ^ ROR64(t.x[3], 10) ^ ROR64(t.x[3], 17);
    s->x[4] = t.x[4] ^ ROR64(t.x[4],  7) ^ ROR64(t.x[4], 41);
  }
}


// The 2nd version of the ASCON128v12 permutation is based on the source code
// in `round.h` of the `opt64_lowsize` implementation from the designers.

void isap_c99_V2(State *s, int nr)
{
  uint64_t xtemp;
  int rc;

  for (rc = START(nr); rc > END; rc -= DEC) {
    // round constant
    s->x[2] ^= (uint64_t) rc;
    // s-box layer
    s->x[0] ^= s->x[4];
    s->x[4] ^= s->x[3];
    s->x[2] ^= s->x[1];
    xtemp = s->x[0] & ~s->x[4];
    s->x[0] ^= s->x[2] & ~s->x[1];
    s->x[2] ^= s->x[4] & ~s->x[3];
    s->x[4] ^= s->x[1] & ~s->x[0];
    s->x[1] ^= s->x[3] & ~s->x[2];
    s->x[3] ^= xtemp;
    s->x[1] ^= s->x[0];
    s->x[3] ^= s->x[2];
    s->x[0] ^= s->x[4];
    s->x[2] = ~s->x[2];
    // linear layer
    xtemp = s->x[0] ^ ROR64(s->x[0], 28 - 19);
    s->x[0] ^= ROR64(xtemp, 19);
    xtemp = s->x[1] ^ ROR64(s->x[1], 61 - 39);
    s->x[1] ^= ROR64(xtemp, 39);
    xtemp = s->x[2] ^ ROR64(s->x[2], 6 - 1);
    s->x[2] ^= ROR64(xtemp, 1);
    xtemp = s->x[3] ^ ROR64(s->x[3], 17 - 10);
    s->x[3] ^= ROR64(xtemp, 10);
    xtemp = s->x[4] ^ ROR64(s->x[4], 41 - 7);
    s->x[4] ^= ROR64(xtemp, 7);
  }
}


// The 3rd version of the ASCON128v12 permutation is based on the source code
// in `opt.c` of the implementation from Campos et al (CANS 2020).

void isap_c99_V3(State *s, int nr)
{
  uint64_t s0 = s->x[0], s1 = s->x[1], s2 = s->x[2];
  uint64_t s3 = s->x[3], s4 = s->x[4];
  uint64_t ta, tb, tc;
  uint64_t r0, r1, r2, r3, r4;
  int rc;

  for (rc = START(nr); rc > END; rc -= DEC) {
    // addition of round constant
    s2 ^= (uint64_t) rc;
    // substitution layer
    ta = s1 ^ s2;
    tb = s0 ^ s4;
    tc = s3 ^ s4;
    s4 = ~s4;
    s4 = s4 | s3;
    s4 = s4 ^ ta;  // s4 contains s->x[2]
    s3 = s3 ^ s1;
    s3 = s3 | ta;
    s3 = s3 ^ tb;  // s3 contains s->x[1]
    s2 = s2 ^ tb;
    s2 = s2 | s1;
    s2 = s2 ^ tc;  // s2 contains s->x[0]
    tb = ~tb;
    s1 = s1 & tb;
    s1 = s1 ^ tc;  // s1 contains s->x[4]
    s0 = s0 | tc;
    s0 = s0 ^ ta;  // s0 contains s->x[3]
    // linear diffusion layer
    r0 = s2; r1 = s3; r2 = s4; r3 = s0; r4 = s1;
    s0 = r0 ^ ROR64(r0, 19) ^ ROR64(r0, 28);
    s1 = r1 ^ ROR64(r1, 61) ^ ROR64(r1, 39);
    s2 = r2 ^ ROR64(r2,  1) ^ ROR64(r2,  6);
    s3 = r3 ^ ROR64(r3, 10) ^ ROR64(r3, 17);
    s4 = r4 ^ ROR64(r4,  7) ^ ROR64(r4, 41);
  }
  s->x[0] = s0;
  s->x[1] = s1;
  s->x[2] = s2;
  s->x[3] = s3;
  s->x[4] = s4;
}


// Print the five state-words of ASCON128v12 in Hex format.

static void print_state(State *s)
{
  UChar buffer[85], byte;
  int i, j, k = 0;

  // printf("%016llx %016llx %016llx ", s->x[0], s->x[1], s->x[2]);
  // printf("%016llx %016llx\n", s->x[3], s->x[4]);

  for (i = 0; i < 5; i++) {
    for (j = 15; j >= 0; j--) {
      byte = (s->x[i] >> 4*j) & 0xf;
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


// Simple test function for the ASCON128v12 permutation.

void isap_test_perm(int rounds)
{
  State s;
  int i;

  // 1st test: state is initialized with all-0 words

  printf("Test 1 - C99 implementation:\n");
  s.x[0] = s.x[1] = s.x[2] = s.x[3] = s.x[4] = 0;
  print_state(&s);
  isap_c99(&s, rounds);  // permutation in C
  print_state(&s);

#if defined(ISAP_ASSEMBLER)
  printf("Test 1 - ASM implementation:\n");
  s.x[0] = s.x[1] = s.x[2] = s.x[3] = s.x[4] = 0;
  print_state(&s);
  isap_asm(&s, rounds);  // permutation in ASM
  print_state(&s);
#endif

  // 2nd test: state is initialized with byte-indeces

  printf("Test 2 - C99 implementation:\n");
  for (i = 0; i < 40; i++) ((uint8_t *) &s)[i] = (uint8_t) i;
  print_state(&s);
  isap_c99(&s, rounds);  // permutation in C
  print_state(&s);

#if defined(ISAP_ASSEMBLER)
  printf("Test 2 - ASM implementation:\n");
  for (i = 0; i < 40; i++) ((uint8_t *) &s)[i] = (uint8_t) i;
  print_state(&s);
  isap_asm(&s, rounds);  // permutation in ASM
  print_state(&s);
#endif

  // Expected result for 6 rounds
  // ----------------------------
  // Test 1 - C99 implementation:
  // 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
  // 160c84f20faad4f1 21495b1b0ae33eef e0377d04e23a914b 2b23481598ffa8ea 649af379ba83cd30
  // Test 1 - ASM implementation:
  // 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000
  // 160c84f20faad4f1 21495b1b0ae33eef e0377d04e23a914b 2b23481598ffa8ea 649af379ba83cd30
  // Test 2 - C99 implementation:
  // 0706050403020100 0f0e0d0c0b0a0908 1716151413121110 1f1e1d1c1b1a1918 2726252423222120
  // eabb307b20741574 69f9b6e6f3c87f1c 3ed22b3cefcfe13d ac5b1fd401664b92 e62f2ef2099605d0
  // Test 2 - ASM implementation:
  // 0706050403020100 0f0e0d0c0b0a0908 1716151413121110 1f1e1d1c1b1a1918 2726252423222120
  // eabb307b20741574 69f9b6e6f3c87f1c 3ed22b3cefcfe13d ac5b1fd401664b92 e62f2ef2099605d0
}
