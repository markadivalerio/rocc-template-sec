#ifndef __RSA_H
#define __RSA_H

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

#define RSA_KEY_BYTES 16
#define RSA_KEY_HALF_WORDS RSA_KEY_BYTES/2

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

void encrypt(rsaData rsa, uint64_t encrypted[7]);
void decrypt(rsaData rsa, uint64_t ciphertext[7], uint64_t decrypted[7]);

uint64_t leftmostbit = 0x8000000000000000ULL;
uint64_t rightmostbit = 0x0000000000000001ULL;

int u128_is_even(uint128 num)
{
  if(num.lo & rightmostbit == 0)
    return TRUE;
  return FALSE;
}

uint128 u128_shift_right(uint128 num)
{
    num.lo >>= 1;
    if(num.hi & rightmostbit == 1)
        num.lo = num.lo | leftmostbit;
    num.hi >>= 1;
    return num;
}

uint128 u128_shift_left(uint128 num)
{
    num.hi <<= 1;
    if(num.lo & leftmostbit != 0)
        num.hi |= rightmostbit;
    num.lo <<= 1;
    return num;
}

uint128 u128_xor(uint128 a, uint128 b)
{
  uint128 res = {(a.hi ^ b.hi), (a.lo ^ b.lo)};
    return res;
}

uint128 u128_and(uint128 a, uint128 b)
{
  uint128 res = {(a.hi & b.hi), (a.lo & b.lo)};
    return res;
}


uint128 u128_subtract(uint128 left, uint128 right)
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

uint128 u128_add(uint128 left, uint128 right)
{
    uint128 result = {0ULL, 0ULL};
    result.hi = left.hi + right.hi;
    result.lo = left.lo + right.lo;
    if(result.lo < left.lo || result.lo < right.lo)
        result.hi += 1;
    // TODO detect overflow?
    return result;
}

uint128 u128_multiply(uint128 a, uint128 b)
{
    uint128 res = {0ULL, 0ULL};
    
    while(b.hi != 0 || b.lo != 0)
    {
        if(b.lo & 1)
            res = u128_add(res, a);
  
        // Double the first number and halve the second number 
        a = u128_shift_left(a);
        b = u128_shift_right(b);
    }
    //printf("Mult: %llu %llu * %llu %llu = %llu %llu \n", a, b, res);
    return res; 
}

uint128 u128_power(uint128 base, uint128 expo)
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

// uint128 u128_gcd(uint128 a, uint128 b)
// {
//  uint128 temp_u = {0x0ULL, 0x1ULL};
//  uint128 temp_v = {0x0ULL, 0x0ULL};
//  uint128 alpha = a;
//  uint128 beta = b;

//  uint128 result = {0x0ULL, 0x1ULL};

//  while(a.hi > 0ULL || a.low > 0ULL)
//  {
//    a = u128_shift_right(a);
//    temp_v = u128_shift_right(temp_v);
//    if(~u128_is_even(temp_u))
//    {
//      temp_u = u128_shift_right(temp_u);
//    }
//    else
//    {
//      temp_v = u128_add(temp_u, alpha);
      
//      temp_u = u128_xor(temp_u, beta);
//      temp_u = u128_shift_right(temp_u);

//    }
//  }
// }

uint128 big_mod_w_subtract(uint128 numerator, uint128 denominator)
{
    uint128 result = {};
    result.hi = numerator.hi;
    result.lo = numerator.lo;
    
    while(result.hi != 0 || result.lo != 0)
    {
        // printf("%llu %llu\n", result.hi, result.lo);
        if(result.hi < denominator.hi || (result.hi == denominator.hi && result.lo < denominator.lo))
        {
            break;
        }
        result = u128_subtract(result, denominator);
    }

    return result;
}

uint128 u128_hybrid_mod(uint128 base, uint128 expo, uint128 mod)
{
    uint128 zero = {0ULL, 0ULL};
    uint128 one = {0ULL, 0ULL};
    if(mod.hi == 0ULL && mod.lo == 1ULL)
    {
        return zero;
    }
    uint128 result = one;
    while(expo.hi != 0ULL || expo.lo != 0ULL)
    {
        // printf("%llu %llu, %llu %llu, %llu %llu. %llu %llu \n", base, expo, mod, result);
        if(expo.lo & rightmostbit != 0)
        {
            result = u128_multiply(result, base);
            result = big_mod_w_subtract(result, mod);
        }
        expo = u128_shift_right(expo);
        base = u128_multiply(base, base);
        base = big_mod_w_subtract(base, mod);
    }
    return result;
}

uint64_t mod_exponentiation(uint64_t base, uint64_t expo, uint64_t mod)
{
    uint64_t result = 1;
    if(mod == 1ULL)
        return 0ULL;
    // printf("\n%llu\n", temp);
    if((mod - 1ULL) * (mod - 1ULL) < mod)
        printf("Warning: Mod will overflow");
    
    //base = base % mod;
    while(expo != 0)
    {
        //printf(".");
        // printf("%llu %llu %llu %llu\n", base, expo, mod, result);
        // printf("%llu ", (expo % 2));
        if(expo % 2ULL == 1ULL)
        {
            result = (result * base) % mod;
            //printf("%llu", result);
        }
        // expo >>= 1ULL;
        expo = expo >> 1;
        // printf("%llu %llu", (base*base), ((base * base) % mod));
        base = (base * base) % mod;
        // if(result > mod)
        // {
        //     result = result % mod;
        // }
        //printf("\n\n");
    }
    return result;
}


typedef unsigned long long uint64;
typedef long long int64;

/* ---------------------------- mulul64 ----------------------------- */

/* Multiply unsigned long 64-bit routine, i.e., 64 * 64 ==> 128.
Parameters u and v are multiplied and the 128-bit product is placed in
(*whi, *wlo). It is Knuth's Algorithm M from [Knu2] section 4.3.1.
Derived from muldwu.c in the Hacker's Delight collection. */

void mulul64(uint64 u, uint64 v, uint64 *whi, uint64 *wlo)
   {
   uint64 u0, u1, v0, v1, k, t;
   uint64 w0, w1, w2;

   u1 = u >> 32; u0 = u & 0xFFFFFFFF;
   v1 = v >> 32; v0 = v & 0xFFFFFFFF;

   t = u0*v0;
   w0 = t & 0xFFFFFFFF;
   k = t >> 32;

   t = u1*v0 + k;
   w1 = t & 0xFFFFFFFF;
   w2 = t >> 32;

   t = u0*v1 + w1;
   k = t >> 32;

   *wlo = (t << 32) + w0;
   *whi = u1*v1 + w2 + k;

   return;
}

/* ---------------------------- modul64 ----------------------------- */

uint64 modul64(uint64 x, uint64 y, uint64 z) {

   /* Divides (x || y) by z, for 64-bit integers x, y,
   and z, giving the remainder (modulus) as the result.
   Must have x < z (to get a 64-bit result). This is
   checked for. */

   int64 i, t;

   printf("In modul64, x = %016llx, y = %016llx, z = %016llx\n", x, y, z);
   if (x >= z) {
      printf("Bad call to modul64, must have x < z.");
      exit(1);
   }
   for (i = 1; i <= 64; i++) {  // Do 64 times.
      t = (int64)x >> 63;       // All 1's if x(63) = 1.
      x = (x << 1) | (y >> 63); // Shift x || y left
      y = y << 1;               // one bit.
      if ((x | t) >= z) {
         x = x - z;
         y = y + 1;
      }
   }
   return x;                    // Quotient is y.
}

/* ---------------------------- montmul ----------------------------- */

uint64 montmul(uint64 abar, uint64 bbar, uint64 m,
               uint64 mprime) {

   uint64 thi, tlo, tm, tmmhi, tmmlo, uhi, ulo, ov;

   printf("\nmontmul, abar = %016llx, bbar   = %016llx\n", abar, bbar);
   printf("            m = %016llx, mprime = %016llx\n", m, mprime);

   /* t = abar*bbar. */

   mulul64(abar, bbar, &thi, &tlo);  // t = abar*bbar.
   printf("montmul, thi = %016llx, tlo = %016llx\n", thi, tlo);

   /* Now compute u = (t + ((t*mprime) & mask)*m) >> 64.
   The mask is fixed at 2**64-1. Because it is a 64-bit
   quantity, it suffices to compute the low-order 64
   bits of t*mprime, which means we can ignore thi. */

   tm = tlo*mprime;
   printf("montmul, tm = %016llx\n", tm);

   mulul64(tm, m, &tmmhi, &tmmlo);   // tmm = tm*m.
   printf("montmul, tmmhi = %016llx, tmmlo = %016llx\n", tmmhi, tmmlo);

   ulo = tlo + tmmlo;                // Add t to tmm
   uhi = thi + tmmhi;                // (128-bit add).
   if (ulo < tlo) uhi = uhi + 1;     // Allow for a carry.

   // The above addition can overflow. Detect that here.

   ov = (uhi < thi) | ((uhi == thi) & (ulo < tlo));
   printf("montmul, sum, uhi = %016llx, ulo = %016llx, ov = %lld\n", uhi, ulo, ov);

   ulo = uhi;                   // Shift u right
   uhi = 0;                     // 64 bit positions.
   printf("montmul, ulo = %016llx\n", ulo);

// if (ov > 0 || ulo >= m)      // If u >= m,
//    ulo = ulo - m;            // subtract m from u.
   ulo = ulo - (m & -(ov | (ulo >= m))); // Alternative
                                // with no branching.
   printf("montmul, final ulo = %016llx\n", ulo);

   if (ulo >= m)
      printf("ERROR in montmul, ulo = %016llx, m = %016llx\n", ulo, m);
   return ulo;
}

/* ---------------------------- xbinGCD ----------------------------- */

/* C program implementing the extended binary GCD algorithm. C.f.
http://www.ucl.ac.uk/~ucahcjm/combopt/ext_gcd_python_programs.pdf. This
is a modification of that routine in that we find s and t s.t.
    gcd(a, b) = s*a - t*b,
rather than the same expression except with a + sign.
   This routine has been greatly simplified to take advantage of the
facts that in the MM use, argument a is a power of 2, and b is odd. Thus
there are no common powers of 2 to eliminate in the beginning. The
parent routine has two loops. The first drives down argument a until it
is 1, modifying u and v in the process. The second loop modifies s and
t, but because a = 1 on entry to the second loop, it can be easily seen
that the second loop doesn't alter u or v. Hence the result we want is u
and v from the end of the first loop, and we can delete the second loop.
   The intermediate and final results are always > 0, so there is no
trouble with negative quantities. Must have a either 0 or a power of 2
<= 2**63. A value of 0 for a is treated as 2**64. b can be any 64-bit
value.
   Parameter a is half what it "should" be. In other words, this function
does not find u and v st. u*a - v*b = 1, but rather u*(2a) - v*b = 1. */

void xbinGCD(uint64 a, uint64 b, uint64 *pu, uint64 *pv)
   {
   uint64 alpha, beta, u, v;
   printf("Doing GCD(%llx, %llx)\n", a, b);

   u = 1; v = 0;
   alpha = a; beta = b;         // Note that alpha is
                                // even and beta is odd.

   /* The invariant maintained from here on is:
   2a = u*2*alpha - v*beta. */

// printf("Before, a u v = %016llx %016llx %016llx\n", a, u, v);
   while (a > 0) {
      a = a >> 1;
      if ((u & 1) == 0) {             // Delete a common
         u = u >> 1; v = v >> 1;      // factor of 2 in
      }                               // u and v.
      else {
         /* We want to set u = (u + beta) >> 1, but
         that can overflow, so we use Dietz's method. */
         u = ((u ^ beta) >> 1) + (u & beta);
         v = (v >> 1) + alpha;
      }
//    printf("After,  a u v = %016llx %016llx %016llx\n", a, u, v);
   }

// printf("At end,    a u v = %016llx %016llx %016llx\n", a, u, v);
   *pu = u;
   *pv = v;
   return;
}



void encrypt(rsaData rsa, uint64_t encrypted[7])
{
  unsigned char message[7] = "Hello !";
  int i;
  uint64_t base = 0ULL;
  uint64_t expo = rsa.pubExp;
  uint64_t mod = rsa.mod.lo;
  for (i = 0; i<7; i++)
  {
    base = (uint64_t)message[i];
    printf("%llu ", base);
    encrypted[i] =  mod_exponentiation(base, expo, mod);
  }
  
}

void decrypt(rsaData rsa, uint64_t ciphertext[7], uint64_t decrypted[7])
{
  int i;
  uint64_t base = 0ULL;
  uint64_t expo = rsa.privateExp.lo;
  uint64_t mod = rsa.mod.lo;
  printf("\nDecrypted: ");
  for (i = 0; i < 7; i++)
  {
    uint64_t temp = mod_exponentiation(ciphertext[i], expo, mod);
    decrypted[i] = temp;
    printf("%llu ", temp);
  }
}


#endif
