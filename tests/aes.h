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
#define xtime(x)   ((x<<1) ^ (((x>>7) & 1) * 0x1b))

void print_state(unsigned char state[4][4], int is_grid);
void encrypt(unsigned char cipher_key[32], unsigned char plaintext[32], unsigned char iv[32], unsigned char * enc_buf);


//Implement AES here

unsigned char sbox[256] =   {
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
 
unsigned char rsbox[256] = {
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

unsigned char mc_box[4][4] = {
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x01, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02}
};

unsigned char rmc_box[4][4] = {
	{0x0E, 0x0B, 0x0D, 0x09},
	{0x09, 0x0E, 0x0B, 0x0D},
	{0x0D, 0x09, 0x0E, 0x0B},
	{0x0B, 0x0D, 0x09, 0x0E}
};

// unsigned char rcon[10] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};
unsigned char rcon[11] = {0x8d,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

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


void substitute_bytes(unsigned char state[4][4], int inverse)
{
	printf("substitute_bytes\n");
	
	int c, r;
	for(r = 0; r < 4; r++)
	{
		for(c = 0; c < 4; c++)
		{
			if(inverse)
			{
				state[r][c] = rsbox[state[r][c]];
			}
			else
			{
				state[r][c] = sbox[state[r][c]];
			}
		}
	}
}


void shift_row(unsigned char * row, signed int delta, int inverse)
//shifts single row left (inverse=false) or right (inverse=true)
{	
	unsigned char temp[4];
	if(delta == 0)
		return;;
	
	for(;delta>0;delta--)
	{
	    if(inverse) // right
	    {
		unsigned char temp = row[3];
		row[3] = row[2];
		row[2] = row[1];
		row[1] = row[0];
		row[0] = temp;
	    }
	    else // left
	    {
		unsigned char temp = row[0];
                row[0] = row[1];
                row[1] = row[2];
                row[2] = row[3];
                row[3] = temp;
	    }
	}
}

void shift_rows(unsigned char state[4][4], int inverse)
{
	printf("shift_rows");
        signed int r;
        for(r = 1; r < 4; r++) // row 0 does not shift.
        {
                shift_row(state[r], r, inverse);
        }
}
unsigned char multiply(unsigned char a, unsigned char b) {
   int i;

   unsigned char c = 0;
   unsigned char d = b;

   for (int i=0 ; i < 8 ; i++) {
      if (a%2 == 1) c ^= d;
      a /= 2;
      d = xtime(d);
   }
   return c;
}

// MixColumns function mixes the columns of the state matrix
void mix_columns2(unsigned char a, unsigned char b, unsigned char c, unsigned char d, unsigned char *temp) {
   int i;
   unsigned char Tmp,Tm,t,e,f,g,h;
   t = a;
   Tmp = a ^ b ^ c ^ d;
   Tm = a ^ b ; 
   Tm = xtime(Tm); 
   e = Tm ^ Tmp ^ a ;
      
   Tm = b ^ c; 
   Tm = xtime(Tm); 
   f = Tm ^ Tmp ^ b;

   Tm = c ^ d ; 
   Tm = xtime(Tm); 
   g = Tm ^ Tmp ^ c;

   Tm = d ^ t ; 
   Tm = xtime(Tm); 
   h = Tm ^ Tmp ^ d;
   temp[0] = e;
   temp[1] = f;
   temp[2] = g;
   temp[3] = h;
   printf("output: a=0x%02x b=0x%02x c=0x%02x d=0x%02x\n",e,f,g,h);
   //return temp;
}


unsigned char mul_column(unsigned char col[4], int row, unsigned char mbox[4][4])
{
	unsigned char * temp[4];
	
	unsigned char res = (
		(col[0] * mbox[row][0])
		+ (col[1] * mbox[row][1])
		+ (col[2] * mbox[row][2])
		+ (col[3] * mbox[row][3]));
	if((res & 0x80) == 0)
	{
		res = res << 1;
		res = res ^ 0x00;
	}
	else
	{
		res = res << 1;
		res = res ^ 0x1b;
	}
	return res;
}

void mix_columns(unsigned char state[4][4], int inverse)
{
	unsigned char mbox[4][4];
	if(inverse)
		memcpy(mbox, rmc_box, sizeof(mbox));
	else
		memcpy(mbox, mc_box, sizeof(mbox)); 
	printf("mix_columns");
	unsigned char temp[4][4] = {{0}};
	int r, c;
	for(c=0;c<4;c++)
	{
	    unsigned char temp[4];
	    mix_columns2(state[0][c], state[1][c], state[2][c], state[3][c], temp);
	    state[0][c] = temp[0];
	    state[1][c] = temp[1];
	    state[2][c] = temp[2];
	    state[3][c] = temp[3];
	}
	/*printf("before ");
	print_state(state, TRUE);
	for(c = 0; c < 4; c++)
	{
		unsigned char col[4] = {state[0][c], state[1][c], state[2][c], state[3][c]};
		for(r = 0; r < 4; r++)
		{
			temp[r][c] = mul_column(col, r, mbox);
		}
	}
	memcpy(state, temp, sizeof(temp));
	
	printf("after ");
	print_state(state, TRUE);*/
}

void add_round_key(unsigned char state[4][4], unsigned char * round_key, int round)
{
	/* XOR corresponding text input and round key input bytes*/
	int i, j;
	for(i = 0;i<4;i++)
	{
		for(j = 0; j < 4; j++)
		{
			state[i][j] ^= round_key[(round * 4 * 4) + (i * 4) + j];
		}
	}
}

void rotate_word(unsigned char * word)
{
	unsigned char temp=word[0];
	word[0] = word[1];
	word[1] = word[2];
	word[2] = word[3];
	word[3] = temp;
}


void sub_word(unsigned char * word)
{
	word[0] = sbox[word[0]];
	word[1] = sbox[word[1]];
	word[2] = sbox[word[2]];
	word[3] = sbox[word[3]];
}

void key_expansion(unsigned char key[32], unsigned char * round_key, int round_number)
{
	int i,j;
	unsigned char temp[4];
	for(i=0;i<4;i++)
	{
		round_key[(i * 4) + 0] = key[(i * 4) + 0];
		round_key[(i * 4) + 1] = key[(i * 4) + 1];
		round_key[(i * 4) + 2] = key[(i * 4) + 2];
		round_key[(i * 4) + 3] = key[(i * 4) + 3];
	}

	for(i=4;i<(4*(round_number+1));++i)
	{
		int k = (i-1) * 4;
		temp[0] = round_key[k + 0];
		temp[1] = round_key[k + 1];
		temp[2] = round_key[k + 2];
		temp[3] = round_key[k + 3];

		if(i % 4 == 0)
		{
			rotate_word(temp);
			sub_word(temp);
			temp[0] = temp[0] ^ rcon[i/4];
		}
		int j = i*4;
		k=(i-4)*4;
		round_key[j + 0] = ((unsigned char)round_key[k + 0]) ^ temp[0];
		round_key[j + 1] = ((unsigned char)round_key[k + 1]) ^ temp[1];
		round_key[j + 2] = ((unsigned char)round_key[k + 2]) ^ temp[2];
		round_key[j + 3] = ((unsigned char)round_key[k + 3]) ^ temp[3];
	}
}

void expand_key2(unsigned char *key, unsigned char *expandedKey)
{
	unsigned short ii, buf1;
  for (ii=0;ii<16;ii++)
    expandedKey[ii] = key[ii];
  for (ii=1;ii<11;ii++){
    buf1 = expandedKey[ii*16 - 4];
    expandedKey[ii*16 + 0] = sbox[expandedKey[ii*16 - 3]]^expandedKey[(ii-1)*16 + 0]^rcon[ii];
    expandedKey[ii*16 + 1] = sbox[expandedKey[ii*16 - 2]]^expandedKey[(ii-1)*16 + 1];
    expandedKey[ii*16 + 2] = sbox[expandedKey[ii*16 - 1]]^expandedKey[(ii-1)*16 + 2];
    expandedKey[ii*16 + 3] = sbox[buf1                  ]^expandedKey[(ii-1)*16 + 3];
    expandedKey[ii*16 + 4] = expandedKey[(ii-1)*16 + 4]^expandedKey[ii*16 + 0];
    expandedKey[ii*16 + 5] = expandedKey[(ii-1)*16 + 5]^expandedKey[ii*16 + 1];
    expandedKey[ii*16 + 6] = expandedKey[(ii-1)*16 + 6]^expandedKey[ii*16 + 2];
    expandedKey[ii*16 + 7] = expandedKey[(ii-1)*16 + 7]^expandedKey[ii*16 + 3];
    expandedKey[ii*16 + 8] = expandedKey[(ii-1)*16 + 8]^expandedKey[ii*16 + 4];
    expandedKey[ii*16 + 9] = expandedKey[(ii-1)*16 + 9]^expandedKey[ii*16 + 5];
    expandedKey[ii*16 +10] = expandedKey[(ii-1)*16 +10]^expandedKey[ii*16 + 6];
    expandedKey[ii*16 +11] = expandedKey[(ii-1)*16 +11]^expandedKey[ii*16 + 7];
    expandedKey[ii*16 +12] = expandedKey[(ii-1)*16 +12]^expandedKey[ii*16 + 8];
    expandedKey[ii*16 +13] = expandedKey[(ii-1)*16 +13]^expandedKey[ii*16 + 9];
    expandedKey[ii*16 +14] = expandedKey[(ii-1)*16 +14]^expandedKey[ii*16 +10];
    expandedKey[ii*16 +15] = expandedKey[(ii-1)*16 +15]^expandedKey[ii*16 +11];
  }
}

unsigned int aes_sub_dword(unsigned int val)
{
    unsigned int tmp = 0;
   
    tmp |= ((unsigned int)sbox[(unsigned char)((val >>  0) & 0xFF)]) <<  0;
    tmp |= ((unsigned int)sbox[(unsigned char)((val >>  8) & 0xFF)]) <<  8;
    tmp |= ((unsigned int)sbox[(unsigned char)((val >> 16) & 0xFF)]) << 16;
    tmp |= ((unsigned int)sbox[(unsigned char)((val >> 24) & 0xFF)]) << 24;

    return tmp;
}

unsigned int aes_rot_dword(unsigned int val)
{
    unsigned int tmp = val;
   
    return (val >> 8) | ((tmp & 0xFF) << 24);
}

unsigned int aes_swap_dword(unsigned int val)
{
    return (((val & 0x000000FF) << 24) |
            ((val & 0x0000FF00) <<  8) |
            ((val & 0x00FF0000) >>  8) |
            ((val & 0xFF000000) >> 24) );
}

void key_expansion3(unsigned char *key, unsigned char *round)
{
    unsigned int *w = (unsigned int *)round;
    unsigned int  t;
    int      i = 0;

    printf("Key Expansion:\n");
    do {
        w[i] = *((unsigned int *)&key[i * 4 + 0]);
 //       printf("    %2.2d:  rs: %8.8x\n", i, aes_swap_dword(w[i]));
    } while (++i < 4);
   
    do {
        printf("    %2.2d: ", i);
        if ((i % 4) == 0) {
            t = aes_rot_dword(w[i - 1]);
   //         printf(" rot: %8.8x", aes_swap_dword(t));
            t = aes_sub_dword(t);
   //         printf(" sub: %8.8x", aes_swap_dword(t));
   //         printf(" rcon: %8.8x", rcon[i/4 - 1]);
            t = t ^ aes_swap_dword(rcon[i/4 - 1]);
   //         printf(" xor: %8.8x", t);
        } else if (4 > 6 && (i % 4) == 4) {
            t = aes_sub_dword(w[i - 1]);
   //         printf(" sub: %8.8x", aes_swap_dword(t));
        } else {
            t = w[i - 1];
   //         printf(" equ: %8.8x", aes_swap_dword(t));
        }
        w[i] = w[i - 4] ^ t;
   //     printf(" rs: %8.8x\n", aes_swap_dword(w[i]));
    } while (++i < 4 * (10 + 1));
   
    /* key can be discarded (or zeroed) from memory */
}


void print_state(unsigned char state[4][4], int as_grid)
{
    int i,j;
    printf("State:\n");
    for(i=0;i<4;i++)
    {
      for(j=0;j<4;j++)
      { 
        printf("%x ", state[i][j] & 0xFF);
      }
      if(as_grid)
        printf("\n");
    }
    printf("\n");
}

void print_key(unsigned char *key)
{
    printf("Key: ");
    int i=0;
    while(key[i] != '\0')
    {
      printf("%x ", key[i] & 0xFF);
      i = i + 1;
    }
    printf("\n");
}

void encrypt(unsigned char cipher_key[32], unsigned char plaintext[32], unsigned char iv[32], unsigned char * enc_buf)
{
	int i,j;
	int round_number;
	int inverse = FALSE;
	unsigned char state[4][4];
	for(i=0;i<32;i++)
	{
		printf("%x ", plaintext[i]);
		int r = (int)i/4;
		state[r][i%4] = plaintext[i] ^ iv[i];
	}
	print_state(state, TRUE);
	//*state = *plaintext;
	unsigned char round_key[128];
	unsigned char expanded_key[128];
	unsigned char expanded_key3[128];
	/* begin with a key addition*/
	printf("-------------------------");
	key_expansion(cipher_key, round_key, 0);
	print_key(round_key);
	expand_key2(cipher_key, expanded_key);
	print_key(expanded_key);
	key_expansion3(cipher_key, expanded_key3);
	print_key(expanded_key3);
	printf("------------------------");
	add_round_key(state, round_key, 0);
	/* ROUNDS-1 ordinary rounds*/
	for(round_number = 1; round_number < 10; round_number++)
	{
		printf("\nRound %d - ", round_number);
		print_key(round_key);
		print_state(state, TRUE);
		substitute_bytes(state, inverse);
		print_state(state, TRUE);
		shift_rows(state, inverse);
		print_state(state, TRUE);
		mix_columns(state, inverse);
		print_state(state, TRUE);
		add_round_key(state, round_key, round_number);
	}
	/* Last round is special: there is no mix_columns*/
	substitute_bytes(state, inverse);
	shift_rows(state, inverse);
	add_round_key(state, round_key, round_number);
	print_state(state, TRUE);
	for(i=0;i<4;i++)
	{
	  for(j=0;j<4;j++)
	  {
	    enc_buf[i*4+j] = state[i][j];
	  }
	}
}

void decrypt(unsigned char *cipher_key, unsigned char *ciphertext, unsigned char * enc_buf)
{
	int round;
	int inverse = FALSE;
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
	unsigned char state[4][4];

	unsigned char *round_key = {0};
        /* begin with a key addition*/
        key_expansion(cipher_key, round_key, 10);
	
	add_round_key(state, round_key, 10);
	shift_rows(state, inverse);
	/* ROUNDS-1 ordinary rounds*/
	for(round = 9;round > 0; round--)
	{
		add_round_key(state, round_key, round);
		mix_columns(state, inverse);
		substitute_bytes(state, inverse);
		shift_rows(state, inverse);
	}

	/* End with the extra key addition*/
	add_round_key(state, round_key, 0);
}




#endif
