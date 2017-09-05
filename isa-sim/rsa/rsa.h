//see LICENSE for license
#ifndef _RISCV_RSA_ROCC_H
#define _RISCV_RSA_ROCC_H

#include "rocc.h"
#include "mmu.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>


class rsa_t : public rocc_t
{
public:
  rsa_t() {};

  const char* name() { return "rsa"; }

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
REGISTER_EXTENSION(rsa, []() { return new rsa_t; })
#endif
