/*
;
; Photon Beetle in MSP430 assembler
; ----------------------------------------
;
; written by Christian Franck and Johann Groﬂsch‰dl
; (c) University of Luxembourg 2023
;
*/


#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <math.h>


static void print_state(uint8_t s[8][8], int transpose)
{
  char buffer[200], b;
  int i, j, k = 0;

  for (i=0; i<8; i++)
  {
    for (j=0; j<8; j++)
    {
      b = s[i][j] & 0xf;
      if (transpose>0) b = s[j][i] & 0xf;
      buffer[k++] = b + ((b < 10) ? 48 : 87);
      buffer[k++] = ' ';
    }
    buffer[k++] = '\n';
  }
    buffer[k++] = '\n';
  buffer[k-1] = '\0';

  printf("%s\n", buffer);
}



// ====================== Version 1: Ref (without table)


#pragma data_alignment=2

uint8_t RC[8][12] = {
    {1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10},
    {0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11},
    {2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9},
    {6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13},
    {14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5},
    {15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4},
    {13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6},
    {9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}
};

uint8_t MixColMatrix[8][8] = {
    { 2,  4,  2, 11,  2,  8,  5,  6},
    {12,  9,  8, 13,  7,  7,  5,  2},
    { 4,  4, 13, 13,  9,  4, 13,  9},
    { 1,  6,  5,  1, 12, 13, 15, 14},
    {15, 12,  9, 13, 14,  5, 14, 13},
    { 9, 14,  5, 15,  4, 12,  9,  6},
    {12,  2,  2, 10,  3,  1,  1, 14},
    {15,  1, 13, 10,  5, 10,  2,  3}
};

uint8_t sbox[16] = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};

void Permutation_ref_c99(uint8_t state[8][8])
{

    int r,i,j,k;
    uint8_t x, y, tmp[8];
    for(r=0; r<12; r++)
    {
        //AddKey(state, i); 
        for(i=0; i<8; i++)
            state[i][0] ^= RC[i][r];
        
        //SubCell(state);
        for(i=0; i<8; i++)
            for(j=0; j<8; j++)
                state[i][j]=sbox[state[i][j]];
        
        //ShiftRow(state);
        for(i=1; i<8; i++)
        {
            for(j=0; j<8; j++)
                tmp[j]=state[i][j];
            for(j=0; j<8; j++)
                state[i][j]=tmp[(j+i)%8];
        }
        
        //MixColumn(state);
        for(j=0; j<8; j++)
        {
            for(i=0; i<8; i++)
            {
                int8_t sum=0;
                for(k=0; k<8; k++)
                {
                    // FieldMult
                    x=MixColMatrix[i][k];
                    y=0;
                    int l;
                    for(l=0; l<4; l++)
                    {
                        if((state[k][j]>>l)&1) y^=x;
                        if((x>>3)&1)
                        {
                            x<<=1;
                            x^=3;
                        }
                        else
                        {
                            x<<=1;
                        }
                    }
                    sum^=y&15;
                }
                tmp[i]=sum;
            }
            for(i=0; i<8; i++)
                state[i][j]=tmp[i];
        }
    }
}



// ====================== Version 2: Ref with table


#pragma data_alignment=2

uint32_t Table[8][16] = {
    {0xBF5C86F8U, 0xA9756B96U, 0xCEB643E4U, 0x5DAB3CD3U, 0x1629ED6EU, 0x00000000U, 0x71EAC51CU, 0x931D7F37U, 0x67C32872U, 0xF4DE5745U, 0xD89FAE8AU, 0x3A6814A1U, 0x85349259U, 0xE2F7BA2BU, 0x2C41F9CFU, 0x4B82D1BDU, },
    {0x565EF4BCU, 0x7B7D93A5U, 0xB3B7E2C6U, 0xACAFD85BU, 0x2D236719U, 0x00000000U, 0xE5E9167AU, 0x1F183A9DU, 0xC8CA7163U, 0xD7D24BFEU, 0x9E9485DFU, 0x6465A938U, 0x323B5D84U, 0xFAF12CE7U, 0x4946CE21U, 0x818CBF42U, },
    {0xBA3969B3U, 0xAEC2B2ACU, 0xC58D3DC8U, 0x5761C156U, 0x14FBDB1FU, 0x00000000U, 0x7FB4547BU, 0x92ECFC9EU, 0x6B4F8F64U, 0xF9A373FAU, 0xD176E6D7U, 0x3C2E4E32U, 0x86172781U, 0xED58A8E5U, 0x28D5952DU, 0x439A1A49U, },
    {0xD33C3811U, 0x1CC5C644U, 0xF8868499U, 0x966B6322U, 0xCFF9FE55U, 0x00000000U, 0x2BBABC88U, 0x6EEDE7BBU, 0xE44342DDU, 0x8AAEA566U, 0x377F7ACCU, 0x722821FFU, 0xA11419EEU, 0x45575B33U, 0xBDD1DFAAU, 0x59929D77U, },
    {0xB26F4579U, 0xA8B937F2U, 0xC13E2BADU, 0x54CD8AE1U, 0x1AD6728BU, 0x00000000U, 0x73516ED4U, 0x95F3A14CU, 0x69871C5FU, 0xFC74BD13U, 0xDBE85926U, 0x3D4A96BEU, 0x8F25D3C7U, 0xE6A2CF98U, 0x279CE435U, 0x4E1BF86AU, },
    {0xA2539FC1U, 0xE87C2954U, 0x51B8DE69U, 0x74A61DB2U, 0x4A2FB695U, 0x00000000U, 0xF3EB41A8U, 0x251EC3DBU, 0xB9C4F73DU, 0x9CDA34E6U, 0x1B9768FCU, 0xCD62EA8FU, 0x6F31754EU, 0xD6F58273U, 0x874D5C1AU, 0x3E89AB27U, },
    {0x993846CBU, 0x22C63B5AU, 0xDD84236CU, 0x11638CB5U, 0xBBFE7D91U, 0x00000000U, 0x44BC65A7U, 0xCCE7AFD9U, 0xFF421836U, 0x33A5B7EFU, 0x667A5EFDU, 0xEE219483U, 0x7719D248U, 0x885BCA7EU, 0x55DFE912U, 0xAA9DF124U, },
    {0xEB643E47U, 0xDAB3CD3FU, 0x7C32872AU, 0xF5C86F8EU, 0x31D7F378U, 0x00000000U, 0x9756B96DU, 0x89FAE8A4U, 0xA6814A15U, 0x2F7BA2B1U, 0x4DE57452U, 0x5349259BU, 0xB82D1BDCU, 0x1EAC51C9U, 0x629ED6E3U, 0xC41F9CF6U, },
};

void Permutation_ref_table_c99(uint8_t state[8][8])
{

    int r,i,j;
    uint32_t v;
    int8_t os[8][8];

    for(r=0; r<12; r++)
    {
        //AddKey(state, i); 
        for(i=0; i<8; i++)
            state[i][0] ^= RC[i][r];

        //SCShRMCS(state);
        memcpy(os, state, 64);
        for(j=0; j<8; j++)
        {
            v=0;
            for(i=0; i<8; i++)
                v ^= Table[i][  os[i][(i+j)%8]  ];

            for(i=1; i<=8; i++)
            {
                state[8-i][j] = (int8_t)v & 15;
                v >>= 4;
            }
        }
    }
}



// ====================== Version 3: Optimized Version "Table1"


#pragma data_alignment=2

uint8_t RC2[12][8] = {
{0x1, 0x0, 0x2, 0x6, 0xe, 0xf, 0xd, 0x9},
{0x3, 0x2, 0x0, 0x4, 0xc, 0xd, 0xf, 0xb},
{0x7, 0x6, 0x4, 0x0, 0x8, 0x9, 0xb, 0xf},
{0xe, 0xf, 0xd, 0x9, 0x1, 0x0, 0x2, 0x6},
{0xd, 0xc, 0xe, 0xa, 0x2, 0x3, 0x1, 0x5},
{0xb, 0xa, 0x8, 0xc, 0x4, 0x5, 0x7, 0x3},
{0x6, 0x7, 0x5, 0x1, 0x9, 0x8, 0xa, 0xe},
{0xc, 0xd, 0xf, 0xb, 0x3, 0x2, 0x0, 0x4},
{0x9, 0x8, 0xa, 0xe, 0x6, 0x7, 0x5, 0x1},
{0x2, 0x3, 0x1, 0x5, 0xd, 0xc, 0xe, 0xa},
{0x5, 0x4, 0x6, 0x2, 0xa, 0xb, 0x9, 0xd},
{0xa, 0xb, 0x9, 0xd, 0x5, 0x4, 0x6, 0x2}
};

const uint64_t Table1[8][16] = {
{0x080f06080c050f0bULL, 0x06090b060507090aULL, 0x040e0304060b0e0cULL, 0x030d0c030b0a0d05ULL,
0x0e060d0e09020601ULL, 0x0000000000000000ULL, 0x0c01050c0a0e0107ULL, 0x07030f070d010309ULL, 
0x02070802030c0706ULL, 0x050407050e0d040fULL, 0x0a080e0a0f09080dULL, 0x010a040108060a03ULL, 
0x0905020904030508ULL, 0x0b020a0b070f020eULL, 0x0f0c090f01040c02ULL, 0x0d0b010d02080b04ULL,},
{0x0c0b040f0e050605ULL, 0x050a03090d070b07ULL, 0x060c020e070b030bULL, 0x0b05080d0f0a0c0aULL, 
0x0901070603020d02ULL, 0x0000000000000000ULL, 0x0a070601090e050eULL, 0x0d090a0308010f01ULL, 
0x030601070a0c080cULL, 0x0e0f0b04020d070dULL, 0x0f0d050804090e09ULL, 0x0803090a05060406ULL, 
0x04080d050b030203ULL, 0x070e0c02010f0a0fULL, 0x01020e0c06040904ULL, 0x02040f0b0c080108ULL,},
{0x030b090609030a0bULL, 0x0c0a020b020c0e0aULL, 0x080c0d030d08050cULL, 0x0605010c01060705ULL, 
0x0f010b0d0b0f0401ULL, 0x0000000000000000ULL, 0x0b070405040b0f07ULL, 0x0e090c0f0c0e0209ULL, 
0x04060f080f040b06ULL, 0x0a0f0307030a090fULL, 0x070d060e0607010dULL, 0x02030e040e020c03ULL, 
0x0108070207010608ULL, 0x050e080a08050d0eULL, 0x0d020509050d0802ULL, 0x09040a010a090304ULL,},
{0x010108030c03030dULL, 0x0404060c050c0c01ULL, 0x090904080608080fULL, 0x020203060b060609ULL, 
0x05050e0f090f0f0cULL, 0x0000000000000000ULL, 0x08080c0b0a0b0b02ULL, 0x0b0b070e0d0e0e06ULL, 
0x0d0d02040304040eULL, 0x0606050a0e0a0a08ULL, 0x0c0c0a070f070703ULL, 0x0f0f010208020207ULL, 
0x0e0e09010401010aULL, 0x03030b0507050504ULL, 0x0a0a0f0d010d0d0bULL, 0x07070d0902090905ULL,},
{0x090705040f06020bULL, 0x020f0703090b080aULL, 0x0d0a0b020e03010cULL, 0x010e0a080d0c0405ULL, 
0x0b080207060d0a01ULL, 0x0000000000000000ULL, 0x040d0e0601050307ULL, 0x0c04010a030f0509ULL, 
0x0f050c0107080906ULL, 0x03010d0b04070c0fULL, 0x06020905080e0b0dULL, 0x0e0b06090a040d03ULL, 
0x070c030d05020f08ULL, 0x08090f0c020a060eULL, 0x0503040e0c090702ULL, 0x0a06080f0b010e04ULL,},
{0x010c0f090305020aULL, 0x040509020c07080eULL, 0x09060e0d080b0105ULL, 0x020b0d01060a0407ULL, 
0x0509060b0f020a04ULL, 0x0000000000000000ULL, 0x080a01040b0e030fULL, 0x0b0d030c0e010502ULL, 
0x0d03070f040c090bULL, 0x060e04030a0d0c09ULL, 0x0c0f080607090b01ULL, 0x0f080a0e02060d0cULL, 
0x0e04050701030f06ULL, 0x03070208050f060dULL, 0x0a010c050d040708ULL, 0x07020b0a09080e03ULL,},
{0x0b0c060408030909ULL, 0x0a050b03060c0202ULL, 0x0c06030204080d0dULL, 0x050b0c0803060101ULL, 
0x01090d070e0f0b0bULL, 0x0000000000000000ULL, 0x070a05060c0b0404ULL, 0x090d0f0a070e0c0cULL, 
0x0603080102040f0fULL, 0x0f0e070b050a0303ULL, 0x0d0f0e050a070606ULL, 0x0308040901020e0eULL, 
0x0804020d09010707ULL, 0x0e070a0c0b050808ULL, 0x0201090e0f0d0505ULL, 0x0402010f0d090a0aULL,},
{0x07040e0304060b0eULL, 0x0f030d0c030b0a0dULL, 0x0a02070802030c07ULL, 0x0e080f06080c050fULL, 
0x0807030f070d0103ULL, 0x0000000000000000ULL, 0x0d06090b06050709ULL, 0x040a080e0a0f0908ULL, 
0x05010a040108060aULL, 0x010b020a0b070f02ULL, 0x02050407050e0d04ULL, 0x0b09050209040305ULL, 
0x0c0d0b010d02080bULL, 0x090c01050c0a0e01ULL, 0x030e060d0e090206ULL, 0x060f0c090f01040cULL,},
};


void Permutation_Table1_c99(uint8_t state[8][8])
{
    int i, c;
    uint64_t t;
    uint8_t os[8][8];
    
    for(i = 0; i < 12; i++) 
    {
        *((uint64_t *)state[0]) ^= *((uint64_t *)RC2[i]);
        
        memcpy(os, state, 64);

        for(c = 0; c < 8; c++) // for all columns
        {
            t = Table1[0][os[(0+c)&7][0]];
            t ^= Table1[1][os[(1+c)&7][1]];
            t ^= Table1[2][os[(2+c)&7][2]];
            t ^= Table1[3][os[(3+c)&7][3]];
            t ^= Table1[4][os[(4+c)&7][4]];
            t ^= Table1[5][os[(5+c)&7][5]];
            t ^= Table1[6][os[(6+c)&7][6]];
            t ^= Table1[7][os[(7+c)&7][7]];
            
            *((uint64_t *)state[c]) = t;
        }
    }
}



// ====================== Version 4: Optimized Assembler Version


#if (defined(__MSP430__) || defined(__ICC430__))
extern void photon_msp(uint8_t s[8][8]);
#define PHOTON_ASSEMBLER
#endif



// ====================== Test Function


#pragma data_alignment=2

// Initialization vector
uint8_t inits[8][8]={
    {0x0,0x0,0x1,0x0,0x2,0x0,0x3,0x0},
    {0x4,0x0,0x5,0x0,0x6,0x0,0x7,0x0},
    {0x8,0x0,0x9,0x0,0xA,0x0,0xB,0x0},
    {0xC,0x0,0xD,0x0,0xE,0x0,0xF,0x0},
    {0x0,0x0,0x1,0x0,0x2,0x0,0x3,0x0},
    {0x4,0x0,0x5,0x0,0x6,0x0,0x7,0x0},
    {0x8,0x0,0x9,0x0,0xA,0x0,0xB,0x0},
    {0xC,0x0,0xD,0x0,0xE,0x0,0xF,0x2}};


void photon_test_perm()
{
    uint8_t s[8][8];
    int i,j;

    printf("Initialization vector:\n");
    print_state(inits,0);
    
    // 1st test
    printf("Output Test 1 - C99 Ref implementation (no table):\n");
    for (i=0;i<8;i++) for (j=0;j<8;j++) s[i][j]=inits[i][j];
    Permutation_ref_c99(s); // measurement: 1313149 cycles
    print_state(s,0);    
    
    // 2nd test
    printf("Output Test 2 - C99 Ref implementation with table:\n");
    for (i=0;i<8;i++) for (j=0;j<8;j++) s[i][j]=inits[i][j];
    Permutation_ref_table_c99(s); // measurement: 186772 cycles
    print_state(s,0);    
  
    // 3rd test
    printf("Output Test 3 - C99 Optimized implementation \"Table1\":\n");
    for (i=0;i<8;i++) for (j=0;j<8;j++) s[i][j]=inits[j][i];
    Permutation_Table1_c99(s); // measurement: 32128 cycles
    print_state(s,1);    
  
#if defined(PHOTON_ASSEMBLER)
    // 4th test
    printf("Output Test 4 - Assembler implementation:\n");
    for (i=0;i<8;i++) for (j=0;j<8;j++) s[i][j]=inits[j][i];
    photon_msp(s); // measurement: 15543 cycles
    print_state(s,1);
#endif   
  

// Expected result 
// ----------------------------
    
//  Initialization vector:
//  0 0 1 0 2 0 3 0 
//  4 0 5 0 6 0 7 0 
//  8 0 9 0 a 0 b 0 
//  c 0 d 0 e 0 f 0 
//  0 0 1 0 2 0 3 0 
//  4 0 5 0 6 0 7 0 
//  8 0 9 0 a 0 b 0 
//  c 0 d 0 e 0 f 2 
//
//  Output Test 1 - C99 Ref implementation (no table):
//  f d e 4 b 0 c a 
//  1 1 2 6 0 4 0 8 
//  8 9 a f c 5 0 f 
//  4 8 8 d 4 f 4 6 
//  1 2 e b 2 f 1 1 
//  1 4 4 3 3 d 5 4 
//  1 2 9 c 5 2 4 6 
//  f b 2 3 d 3 e 3 
//
//  Output Test 2 - C99 Ref implementation with table:
//  f d e 4 b 0 c a 
//  1 1 2 6 0 4 0 8 
//  8 9 a f c 5 0 f 
//  4 8 8 d 4 f 4 6 
//  1 2 e b 2 f 1 1 
//  1 4 4 3 3 d 5 4 
//  1 2 9 c 5 2 4 6 
//  f b 2 3 d 3 e 3 
//
//  Output Test 3 - C99 Optimized implementation "Table1":
//  f d e 4 b 0 c a 
//  1 1 2 6 0 4 0 8 
//  8 9 a f c 5 0 f 
//  4 8 8 d 4 f 4 6 
//  1 2 e b 2 f 1 1 
//  1 4 4 3 3 d 5 4 
//  1 2 9 c 5 2 4 6 
//  f b 2 3 d 3 e 3 
//
//  Output Test 4 - Assembler implementation:
//  f d e 4 b 0 c a 
//  1 1 2 6 0 4 0 8 
//  8 9 a f c 5 0 f 
//  4 8 8 d 4 f 4 6 
//  1 2 e b 2 f 1 1 
//  1 4 4 3 3 d 5 4 
//  1 2 9 c 5 2 4 6 
//  f b 2 3 d 3 e 3 

}



