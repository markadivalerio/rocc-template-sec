//see LICENSE for license
#ifndef _RISCV_SHA3_ROCC_H
#define _RISCV_SHA3_ROCC_H

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
#endif
