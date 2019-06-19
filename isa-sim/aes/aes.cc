#include "rocc.h"
#include "mmu.h"
#include "extension.h"
#include "aes.h"

//Implement AES here

void substitute_bytes(unsigned char a[4][8], unsigned char sbox[4][8])
{
	/* Replace every byte of the input by the byte at that place* in the non-linear S-box*/
	int i, j;
	for(i = 0;i<4;i++)
	{
		for(j = 0; j < BC; j++)
		{
			a[i][j] = sbox[a[i][j]];
		}
	}
}

void shift_rows()
{

}

void add_round_key(unsigned char a[4][8], unsigned char round_key[4][8])
{
	/* XOR corresponding text input and round key input bytes*/
	int i, j;
	for(i = 0;i<4;i++)
	{
		for(j = 0; j < BC; j++)
		{
			a[i][j] ^= round_key[i][j];
		}
	}
}

void mix_columns(unsigned char a[][])
{
	/* Mix the four bytes of every column in a linear way*/
	unsigned char temp[4][8];
	int i, j;
	for(j = 0; j < BC; j++)
	{
		for(i = 0;i<4;i++)
		{
			b[i][j] = mul(2,a[i][j])^ mul(3,a[(i + 1) % 4][j])^ a[(i + 2) % 4][j]^ a[(i + 3) % 4][j];
		}
		for(i = 0;i<4;i++)
		{
			for(j = 0; j < BC; j++)
			{
				a[i][j] = b[i][j];
			}
		}
	}
}

void inv_mix_columns(unsigned char a[][])
{
	/* Mix the four bytes of every column in a linear way* This is the opposite operation of mix_columns*/
	unsigned char temp[4][8];
	int i, j;
	for(j = 0; j < BC; j++)
	{
		for(i = 0;i<4;i++)
		{
			temp[i][j] = mul(0xe,a[i][j])^ mul(0xb,a[(i + 1) % 4][j])^ mul(0xd,a[(i + 2) % 4][j])^ mul(0x9,a[(i + 3) % 4][j]);
		}
		for(i = 0;i<4;i++)
		{
			for(j = 0; j < BC; j++)
			{
				a[i][j] = b[i][j];
			}
		}
	}
}

void key_expansion()
{

}

void encrypt()
{

}

void decrypt()
{

}

void main()
{

}