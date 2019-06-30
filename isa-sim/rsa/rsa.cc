#include "rocc.h"
#include "mmu.h"
#include "extension.h"
#include "rsa.h"

//Implement RSA here
#define TRUE 1
#define FALSE 0

// typedef unsigned long long uint64_t;
//Implement RSA here
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
} rsaData;

int rsa_t::u64_is_even(uint64_t num)
{
  if(num << 63 == 0)
    return TRUE;
  return FALSE;
}

int rsa_t::u128_is_even(uint128 num)
{
  return u64_is_even(num.lo);
}

uint128 rsa_t::u128_shift_right(uint128 num)
{
    num.lo >>= 1;
    if(u64_is_even(num.hi) == FALSE)
        num.lo = num.lo | (0x8000000000000000ULL);
    num.hi >>= 1;
    return num;
}

uint128 rsa_t::u128_shift_left(uint128 num)
{
    num.hi <<= 1;
    if(num.lo >> 63)
        num.hi = num.hi | 0x01;
    num.lo <<= 1;
    return num;
}

uint128 rsa_t::u128_xor(uint128 a, uint128 b)
{
  uint128 res = {(a.hi ^ b.hi), (a.lo ^ b.lo)};
    return res;
}

uint128 rsa_t::u128_and(uint128 a, uint128 b)
{
  uint128 res = {(a.hi & b.hi), (a.lo & b.lo)};
    return res;
}


uint128 rsa_t::u128_subtract(uint128 left, uint128 right)
{
    uint128 result = {0ULL, 0ULL};
    if(left.hi < right.hi || (left.hi == right.hi && left.lo < right.lo))
    {
        printf("WARNING: subtraction underflow");
    }

    result.hi = left.hi - right.hi;
    result.lo = left.lo - right.lo;
    if(result.lo > left.lo)
        result.hi -= 1;
    return result;
}

uint128 rsa_t::u128_add(uint128 left, uint128 right)
{
    uint128 result = {0ULL, 0ULL};
    result.hi = left.hi + right.hi;
    result.lo = left.lo + right.lo;
    if(result.lo < left.lo || result.lo < right.lo)
        result.hi += 1;
    return result;
}

uint128 rsa_t::u128_multiply(uint128 a, uint128 b)
{
    uint128 res = {0ULL, 0ULL};
    
    while(b.hi != 0 || b.lo != 0)
    {
        if(b.lo & 1)
            res = u128_add(res, a);
        a = u128_shift_left(a);
        b = u128_shift_right(b);
    }
    return res; 
}

uint128 rsa_t::u128_power(uint128 base, uint128 expo)
{
    uint128 res = {0ULL, 1ULL};
    while(expo.hi > 0ULL || expo.lo > 0ULL)
    {
        // printf("b%llu %llu ", base);
        // printf("e%llu %llu ", expo);
        // printf("= r = %llu %llu\n", res);
        if(expo.lo & 1ULL)
            res = u128_multiply(res, base);
        base = u128_multiply(base, base);
        expo = u128_shift_right(expo);
    }
    
    return res;
}

uint64_t rsa_t::mod_exponentiation(uint64_t base, uint64_t expo, uint64_t mod)
{
    uint64_t result = 1;
    if(mod == 1ULL)
        return 0ULL;
    if((mod - 1ULL) * (mod - 1ULL) < mod)
        printf("Warning: Mod will overflow");
    
    while(expo != 0)
    {
        if(u64_is_even(expo) == FALSE)
        {
            result = (result * base) % mod;
        }
        expo = expo >> 1;
        base = (base * base) % mod;
    }
    return result;
}


void rsa_t::encrypt(rsaData rsa, const char message[7], uint64_t encrypted[7])
{
  int i;
  for (i = 0; i<7; i++)
  {
    uint64_t base = (uint64_t)message[i];
    encrypted[i] =  mod_exponentiation(base, rsa.pubExp, rsa.mod.lo);
  }
  
}

void rsa_t::decrypt(rsaData rsa, uint64_t ciphertext[7], unsigned char decrypted[7])
{
  int i;
  for (i = 0; i < 7; i++)
  {
    uint64_t temp = mod_exponentiation(ciphertext[i], rsa.privateExp.lo, rsa.mod.lo);
    decrypted[i] = (unsigned char)temp;
  }
}
