//see LICENSE for license
#ifndef _RISCV_RSA_ROCC_H
#define _RISCV_RSA_ROCC_H

#include "rocc.h"
#include "mmu.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef struct uint128 {
  uint64_t hi;
  uint64_t lo;
} uint128;

typedef struct rsaData {
    uint128 prime1;
    uint128 prime2;
    uint64_t pubExp;
    uint128 privateExp;
    uint128 mod;
}
uint64_t leftmostbit = 0x8000000000000000ULL;
uint64_t rightmostbit = 0x0000000000000001ULL;
#define TRUE 1
#define FALSE 0

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

  int u128_is_even(uint128 num);
  uint128 u128_shift_right(uint128 num);
  uint128 u128_shift_left(uint128 num);
  uint128 u128_xor(uint128 a, uint128 b);
  uint128 u128_and(uint128 a, uint128 b);
  uint128 u128_subtract(uint128 left, uint128 right);
  uint128 u128_add(uint128 left, uint128 right);
  uint128 u128_multiply(uint128 a, uint128 b);
  uint128 u128_power(uint128 base, uint128 expo);
  uint128 big_mod_w_subtract(uint128 numerator, uint128 denominator);
  uint128 u128_hybrid_mod(uint128 base, uint128 expo, uint128 mod);
  uint64_t mod_exponentiation(uint64_t base, uint64_t expo, uint64_t mod);
  uint64_t * encrypt(rsaData rsa, unsigned char * message);
  unsigned char * decrypt(rsaData rsa, uint64_t * cipher);

};
REGISTER_EXTENSION(rsa, []() { return new rsa_t; })
#endif
