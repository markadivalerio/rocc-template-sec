//see LICENSE for license
#ifndef _RISCV_AES_ROCC_H
#define _RISCV_AES_ROCC_H

#include "rocc.h"
#include "mmu.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>


class aes_t : public rocc_t
{
public:
  aes_t() {};

  const char* name() { return "aes"; }

  void reset()
  {
    msg_addr = 0;
    hash_addr = 0;
    msg_len = 0;
  }

  reg_t custom0(rocc_insn_t insn, reg_t xs1, reg_t xs2)
  {
    switch (insn.funct)
    {
      case 0: // setup msg and hash addr
        msg_addr = xs1;
        hash_addr = xs2;
        break;
      case 1: // setup msg length and run
        msg_len = xs1;
        unsigned char* input;
        input  = (unsigned char*)malloc(msg_len*sizeof(char));
        for(uint32_t i = 0; i < msg_len; i++)
          input[i] = p->get_mmu()->load_uint8(msg_addr + i);
        unsigned char output[128];
        unsigned char key[32] = {0x60,0x3d,0xeb,0x10,0x15,0xca,0x71,0xbe,0x2b,0x73,0xae,0xf0,0x85,0x7d,0x77,0x81,0x1f,0x35,0x2c,0x07,0x3b,0x61,0x08,0xd7,0x2d,0x98,0x10,0xa3,0x09,0x14,0xdf,0xf4};
        unsigned char iv[16] = {0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,0xff};
        
        aes_encrypt(256, key, iv, input, output, 32, 0);

        //write output
        for(uint32_t i = 0; i < SHA3_256_DIGEST_SIZE; i++)
          p->get_mmu()->store_uint8(hash_addr + i, output[i]);

        free(input);
      default:
        illegal_instruction();
    }

    return -1; // accelerator currently returns nothing
  }
private:
  reg_t msg_addr;
  reg_t hash_addr;
  reg_t msg_len;

#define TRUE 1
#define FALSE 0
#define BLOCK_LEN 16

typedef unsigned char block[4][4];

typedef struct aes_mode {
  int mode;
  int num_cols;
  int num_rnds;
  int key_len;
  int key_exp_len;
  int num_key_words;
  int debug;
} aes_mode;

void debug(char * label, block * state);
void print_arr(char *label, unsigned char * arr, int len);
void print_state(block * state);
void substitute_bytes(block * state);
void shift_rows(block* state);
unsigned char xtime(unsigned char x);
unsigned char multiply(unsigned char a, unsigned char b);
void mix_columns(block* state);
void expand_key(unsigned char * round_key, unsigned char * key);
void add_round_key(block *state, unsigned char *round_key, int round);
void set_mode(int mode, int debug);
void encrypt(block * state, unsigned char * round_key);
void aes_encrypt(int mode, unsigned char * key, unsigned char * iv, unsigned char * input, unsigned char * output, int len, int debug_flag);
void aes_decrypt(int mode, unsigned char * key, unsigned char * iv, unsigned char * input, unsigned char * output, int len, int debug_flag);
{

};
REGISTER_EXTENSION(aes, []() { return new aes_t; })

#endif
