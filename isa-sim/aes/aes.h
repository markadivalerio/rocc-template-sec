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
};
REGISTER_EXTENSION(aes, []() { return new aes_t; })


void substitute_bytes(unsigned char *, bool);
unsigned char * shift_row(unsigned char *, signed int, bool);
void shift_rows(unsigned char *, bool);
unsigned char mul_column(unsigned char, int, bool);
void mix_columns(unsigned char *, bool);
void add_round_key(unsigned char *, unsigned char *, int);
unsigned char * rotate_word(unsigned char *);
unsigned char * sub_word(unsigned char *);
void key_expansion(unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, unsigned char *, unsigned char *);
void decrypt(unsigned char *, unsigned char *, unsigned char *);

#endif
