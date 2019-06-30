#ifndef __AES_H
#define __AES_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define STR1(x) #x
#define STR(x) STR1(x)
#define EXTRACT(a, size, offset) (((~(~0 << size) << offset) & a) >> offset)

#define CUSTOMX_OPCODE(x) CUSTOM_ ## x
#define CUSTOM_0 0b0001011
#define CUSTOM_1 0b0101011
#define CUSTOM_2 0b1011011
#define CUSTOM_3 0b1111011

#define CUSTOMX(X, rd, rs1, rs2, funct)                                 \
    CUSTOMX_OPCODE(X)                   |                               \
                                        (rd                   << (7))       | \
                                        (0x7                  << (7+5))     | \
                                        (rs1                  << (7+5+3))   | \
                                        (rs2                  << (7+5+3+5)) | \
                                        (EXTRACT(funct, 7, 0) << (7+5+3+5+5))



// rd, rs1, and rs2 are data
// rd_n, rs_1, and rs2_n are the register numbers to use
#define ROCC_INSTRUCTION_R_R_R(X, rd, rs1, rs2, funct, rd_n, rs1_n, rs2_n) { \
        register uint64_t rd_  asm ("x" # rd_n);                        \
        register uint64_t rs1_ asm ("x" # rs1_n) = (uint64_t) rs1;      \
        register uint64_t rs2_ asm ("x" # rs2_n) = (uint64_t) rs2;      \
        asm volatile (                                                  \
            ".word " STR(CUSTOMX(X, rd_n, rs1_n, rs2_n, funct)) "\n\t"  \
            : "=r" (rd_)                                                \
            : [_rs1] "r" (rs1_), [_rs2] "r" (rs2_));                    \
        rd = rd_;                                                       \
    }

// Standard macro that passes rd, rs1, and rs2 via registers
#define ROCC_INSTRUCTION(X, rd, rs1, rs2, funct)                \
    ROCC_INSTRUCTION_R_R_R(X, rd, rs1, rs2, funct, 10, 11, 12)


#define read_csr(reg) ({ unsigned long __tmp; \
  asm volatile ("csrr %0, " #reg : "=r"(__tmp)); \
  __tmp; })

#define write_csr(reg, val) ({ \
  asm volatile ("csrw " #reg ", %0" :: "rK"(val)); })

#define swap_csr(reg, val) ({ unsigned long __tmp; \
  asm volatile ("csrrw %0, " #reg ", %1" : "=r"(__tmp) : "rK"(val)); \
  __tmp; })

#define set_csr(reg, bit) ({ unsigned long __tmp; \
  asm volatile ("csrrs %0, " #reg ", %1" : "=r"(__tmp) : "rK"(bit)); \
  __tmp; })

#define clear_csr(reg, bit) ({ unsigned long __tmp; \
  asm volatile ("csrrc %0, " #reg ", %1" : "=r"(__tmp) : "rK"(bit)); \
  __tmp; })

#define rdtime() read_csr(time)
#define rdcycle() read_csr(cycle)
#define rdinstret() read_csr(instret)

#define TRUE 1
#define FALSE 0
#define BLOCK_LEN 16
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

typedef unsigned char uchar;
typedef uchar block[4][4];

typedef struct aes_mode {
  int mode;
  int num_cols;
  int num_rnds;
  int key_len;
  int key_exp_len;
  int num_key_words;
  int inverse;
} aes_mode;

aes_mode aes;//global aes
aes_mode aes2;//global aes



void print_arr(char *label, uchar * arr, int len);
void print_state(block *state);
void aes_encrypt(int mode, uchar * key, uchar * iv, uchar * input, uchar * output, int len, int is_decrypt);
//void decrypt(unsigned char cipher_key[32], unsigned char *ciphertext, unsigned char * deciphered_text);




static const uchar sbox[256] =   {
//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F
 
static const uchar rsbox[256] = {
0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, //0
0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, //1
0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, //2
0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, //3
0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, //4
0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, //5
0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, //6
0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, //7
0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, //8
0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, //9
0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, //A
0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, //B
0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, //C
0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, //D
0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, //E
0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d }; //F

static const uchar mcbox[4][4] = {
  {0x02, 0x03, 0x01, 0x01},
  {0x01, 0x02, 0x03, 0x01},
  {0x01, 0x01, 0x02, 0x03},
  {0x03, 0x01, 0x01, 0x02}
};

static const uchar rmcbox[4][4] = {
  {0x0E, 0x0B, 0x0D, 0x09},
  {0x09, 0x0E, 0x0B, 0x0D},
  {0x0D, 0x09, 0x0E, 0x0B},
  {0x0B, 0x0D, 0x09, 0x0E}
};

uchar rcon[11] = {0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};




// The round constant word array, Rcon[i], contains the values given by
// x to th e power (i-1) being powers of x (x is denoted as {02}) in the field GF(2^8)
// Note that i starts at 1, not 0).
// int rcon[255] = {

// 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
// 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
// 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
// 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
// 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
// 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
// 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
// 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
// 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
// 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
// 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
// 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
// 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
// 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
// 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
// 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb  };
void print_arr(char *label, uchar * arr, int len)
{
    printf("%s: ",label);
    for(int i=0;i<len;i++)
    {
        printf("%x", arr[i]);
        if(i%4 == 3)
          printf(" ");
    }
    printf("\n");
}

void print_state(block * state)
{
    int i,j;
    printf("State:\n");
    for(i=0;i<4;i++)
    {
      for(j=0;j<4;j++)
      { 
        printf("%x ", (*state)[i][j] & 0xFF);
      }
      printf("\n");
    }
    printf("\n");
}

void substitute_bytes(block * state)
{
  int c, r;
  for(r = 0; r < 4; r++)
  {
    for(c = 0; c < 4; c++)
    {
      if(aes.inverse)
        (*state)[r][c] = rsbox[(*state)[r][c]];
      else
        (*state)[r][c] = sbox[(*state)[r][c]];
    }
  }
}


// void shift_row(uchar * row, signed int delta)
// //shifts single row left (inverse=false) or right (inverse=true)
// {  
//  uchar temp[4];
//   int right = TRUE;
//  if(delta == 0)
//    return;

//   if(delta < 0)
//   {
//     delta *= -1;
//     right = FALSE;
//   }
  
//  for(;delta>0;delta--)
//  {
//    if(right)
//    {
//      const uchar temp = row[3];
//      row[3] = row[2];
//      row[2] = row[1];
//      row[1] = row[0];
//      row[0] = temp;
//    }
//    else // left
//    {
//        const uchar temp = row[0];
//         row[0] = row[1];
//         row[1] = row[2];
//         row[2] = row[3];
//         row[3] = temp;
//    }
//  }
// }

// void shift_rows(block * state)
// {
//  printf("shift_rows ");
//   signed int r;
//   for(r = 1; r < 4; r++) // row 0 does not shift.
//   {
//       shift_row(state[r], r);
//   }
// }

void shift_rows(block* state)
{
  uchar temp;

  // Rotate first row 1 columns to left  
  temp           = (*state)[0][1];
  (*state)[0][1] = (*state)[1][1];
  (*state)[1][1] = (*state)[2][1];
  (*state)[2][1] = (*state)[3][1];
  (*state)[3][1] = temp;

  // Rotate second row 2 columns to left  
  temp           = (*state)[0][2];
  (*state)[0][2] = (*state)[2][2];
  (*state)[2][2] = temp;

  temp           = (*state)[1][2];
  (*state)[1][2] = (*state)[3][2];
  (*state)[3][2] = temp;

  // Rotate third row 3 columns to left
  temp           = (*state)[0][3];
  (*state)[0][3] = (*state)[3][3];
  (*state)[3][3] = (*state)[2][3];
  (*state)[2][3] = (*state)[1][3];
  (*state)[1][3] = temp;
}


// unsigned char multiply(unsigned char a, unsigned char b) {
//    int i;

//    unsigned char c = 0;
//    unsigned char d = b;

//    for (int i=0 ; i < 8 ; i++) {
//       if (a%2 == 1) c ^= d;
//       a /= 2;
//       d = xtime(d);
//    }
//    return c;
// }
uchar multiply(uchar x, uchar y)
{
  return (((y & 1) * x) ^
       ((y>>1 & 1) * xtime(x)) ^
       ((y>>2 & 1) * xtime(xtime(x))) ^
       ((y>>3 & 1) * xtime(xtime(xtime(x)))) ^
       ((y>>4 & 1) * xtime(xtime(xtime(xtime(x)))))); /* this last call to xtime() can be omitted */
  }

// MixColumns function mixes the columns of the state matrix
void mix_columns(block* state)
{
  uint8_t i;
  uint8_t Tmp, Tm, t;
  for (i = 0; i < 4; ++i)
  {  
    t   = (*state)[i][0];
    Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2] ^ (*state)[i][3] ;
    Tm  = (*state)[i][0] ^ (*state)[i][1] ; Tm = xtime(Tm);  (*state)[i][0] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][1] ^ (*state)[i][2] ; Tm = xtime(Tm);  (*state)[i][1] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][2] ^ (*state)[i][3] ; Tm = xtime(Tm);  (*state)[i][2] ^= Tm ^ Tmp ;
    Tm  = (*state)[i][3] ^ t ;              Tm = xtime(Tm);  (*state)[i][3] ^= Tm ^ Tmp ;
  }
}
// // MixColumns function mixes the columns of the state matrix
// void mix_columns2(unsigned char a, unsigned char b, unsigned char c, unsigned char d, unsigned char *temp) {
//    int i;
//    unsigned char Tmp,Tm,t,e,f,g,h;
//    t = a;
//    Tmp = a ^ b ^ c ^ d;
//    Tm = a ^ b ; 
//    Tm = xtime(Tm); 
//    e = Tm ^ Tmp ^ a ;
      
//    Tm = b ^ c; 
//    Tm = xtime(Tm); 
//    f = Tm ^ Tmp ^ b;

//    Tm = c ^ d ; 
//    Tm = xtime(Tm); 
//    g = Tm ^ Tmp ^ c;

//    Tm = d ^ t ; 
//    Tm = xtime(Tm); 
//    h = Tm ^ Tmp ^ d;
//    temp[0] = e;
//    temp[1] = f;
//    temp[2] = g;
//    temp[3] = h;
//    printf("output: a=0x%02x b=0x%02x c=0x%02x d=0x%02x\n",e,f,g,h);
//    //return temp;
// }


// unsigned char mul_column(unsigned char col[4], int row, unsigned char mbox[4][4])
// {
//  unsigned char * temp[4];
  
//  unsigned char res = (
//    (col[0] * mbox[row][0])
//    + (col[1] * mbox[row][1])
//    + (col[2] * mbox[row][2])
//    + (col[3] * mbox[row][3]));
//  if((res & 0x80) == 0)
//  {
//    res = res << 1;
//    res = res ^ 0x00;
//  }
//  else
//  {
//    res = res << 1;
//    res = res ^ 0x1b;
//  }
//  return res;
// }

// void mix_columns(unsigned char state[4][4], int inverse)
// {
//  unsigned char mbox[4][4];
//  if(inverse)
//    memcpy(mbox, rmc_box, sizeof(mbox));
//  else
//    memcpy(mbox, mc_box, sizeof(mbox)); 
//  printf("mix_columns");
//  unsigned char temp[4][4] = {{0}};
//  int r, c;
//  for(c=0;c<4;c++)
//  {
//      unsigned char temp[4];
//      mix_columns2(state[0][c], state[1][c], state[2][c], state[3][c], temp);
//      state[0][c] = temp[0];
//      state[1][c] = temp[1];
//      state[2][c] = temp[2];
//      state[3][c] = temp[3];
//  }
//  /*printf("before ");
//  print_state(state, TRUE);
//  for(c = 0; c < 4; c++)
//  {
//    unsigned char col[4] = {state[0][c], state[1][c], state[2][c], state[3][c]};
//    for(r = 0; r < 4; r++)
//    {
//      temp[r][c] = mul_column(col, r, mbox);
//    }
//  }
//  memcpy(state, temp, sizeof(temp));
  
//  printf("after ");
//  print_state(state, TRUE);*/
// }

// void rotate_word(uchar * word)
// {
//   const uchar temp = word[0];
//   word[0] = word[1];
//   word[1] = word[2];
//   word[2] = word[3];
//   word[3] = temp;
// }

// void sub_word(uchar * word)
// {
//   word[0] = sbox[word[0]];
//   word[1] = sbox[word[1]];
//   word[2] = sbox[word[2]];
//   word[3] = sbox[word[3]];
// }

void set_word(uchar * left, int lidx, uchar * right, int ridx)
{
  left[lidx + 0] = right[ridx + 0];
  left[lidx + 1] = right[ridx + 1];
  left[lidx + 2] = right[ridx + 2];
  left[lidx + 3] = right[ridx + 3];
}

void expand_key(uchar * round_key, uchar * key)
{
  int i, j, k;
  uchar temp[4]; // Used for the column/row operations
  
  // The first round key is the key itself.
  for (i = 0; i < aes.num_key_words; ++i)
  {
    // set_word(round_key, (i*4), key, (i*4));
    round_key[(i * 4) + 0] = key[(i * 4) + 0];
    round_key[(i * 4) + 1] = key[(i * 4) + 1];
    round_key[(i * 4) + 2] = key[(i * 4) + 2];
    round_key[(i * 4) + 3] = key[(i * 4) + 3];
  }

  // All other round keys are found from the previous round keys.
  for (i = aes.num_key_words; i < 4 * (aes.num_rnds + 1); ++i)
  {
    k = (i - 1) * 4;
    // set_word(temp, 0, round_key, k);
    temp[0]=round_key[k + 0];
    temp[1]=round_key[k + 1];
    temp[2]=round_key[k + 2];
    temp[3]=round_key[k + 3];

    if (i % aes.num_key_words == 0)
    {
      const uchar u8tmp = temp[0];
      temp[0] = temp[1];
      temp[1] = temp[2];
      temp[2] = temp[3];
      temp[3] = u8tmp;

      // sub_word(temp);
      temp[0] = sbox[temp[0]];
      temp[1] = sbox[temp[1]];
      temp[2] = sbox[temp[2]];
      temp[3] = sbox[temp[3]];

      temp[0] ^= rcon[i/aes.num_key_words];
    }

    // if(aes.mode == 256 && i % aes.num_key_words == 4)
    if(i % 8 == 4)
    {
      temp[0] = sbox[temp[0]];
      temp[1] = sbox[temp[1]];
      temp[2] = sbox[temp[2]];
      temp[3] = sbox[temp[3]];
    }
    j = i * 4;
    k = (i - aes.num_key_words) * 4;
    round_key[j + 0] = round_key[k + 0] ^ temp[0];
    round_key[j + 1] = round_key[k + 1] ^ temp[1];
    round_key[j + 2] = round_key[k + 2] ^ temp[2];
    round_key[j + 3] = round_key[k + 3] ^ temp[3];
  }
}

void add_round_key(block *state, uchar *round_key, int round)
{
  // static void AddRoundKey(uint8_t round, state_t* state, const uint8_t* RoundKey)
  uchar i, j;
  for(i = 0; i < 4; ++i)
  {
    for (j = 0; j < 4; ++j)
    {
      (*state)[i][j] ^= round_key[(round * 16) + (i * 4) + j];
    }
  }
}




void set_mode(int mode, int inverse, int is_decrypt)
{
    if(!is_decrypt)
    {
        aes = (aes_mode){
          mode,
          4, // num_cols
          10, // num_rnds
          16, // key_len
          176, // key_exp_len
          4, // num_key_words
          inverse
        };
    
        if(mode == 192)
        {
          aes.num_cols = 5;
          aes.num_rnds = 12;
          aes.key_len = 24;
          aes.key_exp_len = 208;
          aes.num_key_words = 6;
        }
        if(mode == 256)
        {
          aes.num_cols = 6;
          aes.num_rnds = 14;
          aes.key_len = 32;
          aes.key_exp_len = 240;
          aes.num_key_words = 8;
        }
    }
    else
    {
        aes2 = (aes_mode){
          mode,
          4, // num_cols
          10, // num_rnds
          16, // key_len
          176, // key_exp_len
          4, // num_key_words
          inverse
        };
    
        if(mode == 192)
        {
          aes2.num_cols = 5;
          aes2.num_rnds = 12;
          aes2.key_len = 24;
          aes2.key_exp_len = 208;
          aes2.num_key_words = 6;
        }
        if(mode == 256)
        {
          aes2.num_cols = 6;
          aes2.num_rnds = 14;
          aes2.key_len = 32;
          aes2.key_exp_len = 240;
          aes2.num_key_words = 8;
        }
        // aes.num_key_words = aes.key_exp_len / 32;
        memcpy(&aes, &aes2, sizeof(aes2));
    }
     
}

void encrypt(block * state, uchar * round_key)
{
  uchar round = 0;
  // Add the First round key to the state before starting the rounds.
  // print_state(state);
  add_round_key(state, round_key, 0); 
  // print_state(state);
  // There will be Nr rounds.
  // The first Nr-1 rounds are identical.
  // These Nr-1 rounds are executed in the loop below.
  for(round = 1; round < aes.num_rnds; ++round)
  {
    substitute_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, round_key, round);
    
  }
  
  // The last round is given below.
  // The MixColumns function is not here in the last round.
  substitute_bytes(state);
  shift_rows(state);
  add_round_key(state, round_key, aes.num_rnds);
}

void aes_encrypt(int mode, uchar * key, uchar * iv, uchar * input, uchar * output, int len, int is_decrypt)
{
  uchar state[BLOCK_LEN];
  unsigned i;
  int bi;
  set_mode(mode, FALSE, is_decrypt);
  uchar round_key[512];
  expand_key(round_key, key);
  
  // print_arr("IV", iv, 16);
  // print_arr("Round Key:", round_key, 32);
  for (i = 0, bi = BLOCK_LEN; i < len; ++i, ++bi)
  {
    if (bi == BLOCK_LEN) // we need to regen xor compliment in buffer 
    {
      memcpy(state, iv, BLOCK_LEN);
      print_state((block *)state);
      encrypt((block*)state, round_key);
       // Increment Iv and handle overflow
      for (bi = (BLOCK_LEN - 1); bi >= 0; --bi)
      {
        // inc will overflow
        if (iv[bi] == 255)
        {
          iv[bi] = 0;
          continue;
        }
        iv[bi] += 1;
        break;   
      }
      bi = 0;
    }

    output[i] = (input[i] ^ state[bi]);
  }
}

void decrypt(unsigned char cipher_key[32], unsigned char * ciphertext, unsigned char * decyphered_text)
{
  int i,j;
  int round;
  int inverse = TRUE;
  /* To decrypt:
   *   apply the inverse operations of the encrypt routine,
   *   in opposite order
   *
   * - AddRoundKey is equal to its inverse)
   * - the inverse of SubBytes with table S is
   *             SubBytes with the inverse table of S)
   * - the inverse of Shiftrows is Shiftrows over
   *       a suitable distance)*/

  /* First the special round:
   *   without InvMixColumns
   *   with extra AddRoundKey
  */
//  unsigned char state[4][4];
//  int iterations = sizeof(ciphertext)/4;
/*  for(int i = 0; i < 4; ++i)
  {
        state[i][0] = ciphertext[i*4];
    state[i][1] = ciphertext[i*4+1];
    state[i][2] = ciphertext[i*4+2];
    state[i][3] = ciphertext[i*4+3];
  }*/
  //unsigned char round_key[128];
  //key_expansion3(cipher_key, round_key);

        /* begin with a key addition*/
//        key_expansion(cipher_key, expanded_key, 9);
//  print_key(cipher_key);  
//  add_round_key(state, expanded_key, 10);
//  shift_rows(state, inverse);
  /* ROUNDS-1 ordinary rounds*/
/*  for(round = 9;round > 0; round--)
  {
    add_round_key(state, round_key, round);
    mix_columns(state, inverse);
    substitute_bytes(state, inverse);
    shift_rows(state, inverse);
                print_state(state, TRUE);
  }
*/
  /* End with the extra key addition*/
//  add_round_key(state, round_key, 0);
//  print_state(state, TRUE);
}




/*
int main()
{
    uchar key[32] = {   0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,
                        0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,
                        0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,
                        0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
    
    uchar iv[16] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
    uchar iv2[16] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
    
    uchar in[32] = {    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    uchar in2[32] = {    0x6b,0xc1,0xbe,0xe2,0x2e,0x40,0x9f,0x96,
                        0xe9,0x3d,0x7e,0x11,0x73,0x93,0x17,0x2a,
                        0xae,0x2d,0x8a,0x57,0x1e,0x03,0xac,0x9c,
                        0x9e,0xb7,0x6f,0xac,0x45,0xaf,0x8e,0x51};
    
    uchar expected_out[32] = {   0x60,0x1e,0xc3,0x13,0x77,0x57,0x89,0xa5,
                        0xb7,0xa7,0xf5,0x04,0xbb,0xf3,0xd2,0x28,
                        0xf4,0x43,0xe3,0xca,0x4d,0x62,0xb5,0x9a,
                        0xca,0x84,0xe9,0x90,0xca,0xca,0xf5,0xc5};
    uchar out[32];
    uchar out2[32];
    
    aes_encrypt(256, key, iv, in, out, 32, FALSE);
    
    // print_state((block*)out);
    print_arr("Encrypted", out, 32);
    
    printf("\n\n");
    
    uchar iv3[16];
    memcpy(iv3, out, 16);
    aes_encrypt(256, key, iv2, out, out2, 32, TRUE);
    
    print_state((block*)out2);
    
}*/


#endif
