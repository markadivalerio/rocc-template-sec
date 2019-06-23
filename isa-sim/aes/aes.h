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
  }

  reg_t custom0(rocc_insn_t insn, reg_t xs1, reg_t xs2)
  {
    switch (insn.funct)
    {

      default:
        illegal_instruction();
    }

    return -1; // accelerator currently returns nothing
  }

void substitute_bytes(unsigned char * state[4], bool inverse);
unsigned char * shift_row(unsigned char row[4], signed int delta, bool inverse);
void shift_rows(unsigned char * state[4], bool inverse);
unsigned char mul_column(unsigned char col[4], int row, bool inverse);
void mix_columns(unsigned char * state[4], bool inverse);
void add_round_key(unsigned char * state[4], unsigned char * round_key, int round);
unsigned char * rotate_word(unsigned char word[4]);
unsigned char * sub_word(unsigned char word[4]);
void key_expansion(unsigned char key[32], unsigned char *round_key, int round_number);
void encrypt(unsigned char cipher_key[32], unsigned char * plaintext, unsigned char * enc_buf);
void decrypt(unsigned char *cipher_key, unsigned char *ciphertext, unsigned char * enc_buf);

};
REGISTER_EXTENSION(aes, []() { return new aes_t; })

#endif
