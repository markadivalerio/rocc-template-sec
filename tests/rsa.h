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

// typedef unsigned long long uint64_t;
typedef long long int64;

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

void encrypt(rsaData rsa, uint128 * encrypted);
void decrypt(rsaData rsa, uint128 ciphertext[7], char * decrypted);

void print(uint128 num)
{
    printf("%llx %llx \n", num);
}

int u64_is_even(uint64_t num)
{
  if(num << 63 == 0ULL)
    return TRUE;
  return FALSE;
}

int u128_is_even(uint128 num)
{
  return u64_is_even(num.lo);
}

uint128 u128_shift_right(uint128 num)
{
    num.lo >>= 1;
    if(u64_is_even(num.hi) == FALSE)
        num.lo = num.lo | (0x1 << 63);
    num.hi >>= 1;
    return num;
}

uint128 u128_shift_left(uint128 num)
{
    num.hi <<= 1;
    if(num.lo >> 63)
        num.hi = num.hi | 0x01;
    num.lo <<= 1;
    return num;
}

uint128 u128_xor(uint128 a, uint128 b)
{
  uint128 res = (uint128) {(a.hi ^ b.hi), (a.lo ^ b.lo)};
  return res;
}

uint128 u128_and(uint128 a, uint128 b)
{
  uint128 res = (uint128){(a.hi & b.hi), (a.lo & b.lo)};
  return res;
}

int u128_compare(uint128 a, uint128 b)
{
  return  (((a.hi > b.hi) || ((a.hi == b.hi) && (a.lo > b.lo))) ? 1 : 0) 
     -  (((a.hi < b.hi) || ((a.hi == b.hi) && (a.lo < b.lo))) ? 1 : 0);
}


size_t nlz64(uint64_t N)
{
    uint64_t I;
    size_t C;

    I = ~N;
    C = ((I ^ (I + 1)) & I) >> 63;

    I = (N >> 32) + 0xffffffff;
    I = ((I & 0x100000000) ^ 0x100000000) >> 27;
    C += I;  N <<= I;

    I = (N >> 48) + 0xffff;
    I = ((I & 0x10000) ^ 0x10000) >> 12;
    C += I;  N <<= I;

    I = (N >> 56) + 0xff;
    I = ((I & 0x100) ^ 0x100) >> 5;
    C += I;  N <<= I;

    I = (N >> 60) + 0xf;
    I = ((I & 0x10) ^ 0x10) >> 2;
    C += I;  N <<= I;

    I = (N >> 62) + 3;
    I = ((I & 4) ^ 4) >> 1;
    C += I;  N <<= I;

    C += (N >> 63) ^ 1;

    return C;
}

size_t ntz64(uint64_t N)
{
    uint64_t I = ~N;
    size_t C = ((I ^ (I + 1)) & I) >> 63;

    I = (N & 0xffffffff) + 0xffffffff;
    I = ((I & 0x100000000) ^ 0x100000000) >> 27;
    C += I;  N >>= I;

    I = (N & 0xffff) + 0xffff;
    I = ((I & 0x10000) ^ 0x10000) >> 12;
    C += I;  N >>= I;

    I = (N & 0xff) + 0xff;
    I = ((I & 0x100) ^ 0x100) >> 5;
    C += I;  N >>= I;

    I = (N & 0xf) + 0xf;
    I = ((I & 0x10) ^ 0x10) >> 2;
    C += I;  N >>= I;

    I = (N & 3) + 3;
    I = ((I & 4) ^ 4) >> 1;
    C += I;  N >>= I;

    C += ((N & 1) ^ 1);

    return C;
}

size_t nlz128(uint128 N) // Number of Leading Zeros
{
    return (N.hi == 0) ? nlz64(N.lo) + 64 : nlz64(N.hi);
}

size_t ntz128(uint128 N) // number of trailing zeros
{
    return (N.lo == 0) ? ntz64(N.hi) + 64 : ntz64(N.lo);
}

uint128 u128_subtract(uint128 left, uint128 right)
{
    uint128 result = {0ULL, 0ULL};
    if(left.hi < right.hi || (left.hi == right.hi && left.lo < right.lo))
    {
        printf("\n\n---WARNING: subtraction underflow---\n\n");
    }

    result.hi = left.hi - right.hi;
    result.lo = left.lo - right.lo;
    if(result.lo > left.lo)
        result.hi -= 1;
    return result;
}


uint128 u128_add(uint128 left, uint128 right)
{
    uint128 res;
    res.hi = left.hi + right.hi;
    res.lo = left.lo + right.lo;
    if(res.lo < left.lo || res.lo < right.lo)
        res.hi += 1;
    // TODO detect overflow?
    return res;
}

uint128 mult64to128(uint64_t u, uint64_t v)
{
    uint64_t h, l;
        uint64_t u1 = (u & 0xffffffff);
        uint64_t v1 = (v & 0xffffffff);
        uint64_t t = (u1 * v1);
        uint64_t w3 = (t & 0xffffffff);
        uint64_t k = (t >> 32);

        u >>= 32;
        t = (u * v1) + k;
        k = (t & 0xffffffff);
        uint64_t w1 = (t >> 32);

        v >>= 32;
        t = (u1 * v) + k;
        k = (t >> 32);

        h = (u * v) + w1 + k;
        l = (t << 32) + w3;

    uint128 res = {h, l};
    return res;
}

uint128 mult128(uint128 N, uint128 M)
{
    uint128 res = mult64to128(N.lo, M.lo);
        res.hi += (N.hi * M.lo) + (N.lo * M.hi);
    return res;
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

uint128 big_mod_w_subtract(uint128 numerator, uint128 denominator)
{
    uint128 result = {};
    result.hi = numerator.hi;
    result.lo = numerator.lo;
    
    while(result.hi != 0 || result.lo != 0)
    {
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
        if(u128_is_even(expo) == TRUE)
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
/*
uint64_t mod_exponentiation(uint64_t base, uint64_t expo, uint64_t mod)
{
    uint64_t result = 1;
    if(mod == 1ULL)
        return 0ULL;
    if((mod - 1ULL) * (mod - 1ULL) < mod)
        printf("Warning: Mod will overflow");
    
    //base = base % mod;
    while(expo != 0)
    {
        if(expo % 2ULL == 1ULL)
        {
            result = (result * base) % mod;
            //printf("%llu", result);
        }
        expo = expo >> 1;
        base = (base * base) % mod;
    }
    return result;
}*/
/*
uint128 mod_exponentiation(uint128 base, uint128 expo, uint128 mod)
{
    uint128 result = {0ULL, 1ULL};
    uint128 zero = {0ULL, 0ULL};
    uint128 one = {0ULL, 1ULL};
    if(u128_compare(mod, one) == 0)
    {
        return zero;
    }
    //if((mod - 1ULL) * (mod - 1ULL) < mod)
    //    printf("Warning: Mod will overflow");
    
    //base = base % mod;
    while(u128_compare(expo,zero) != 0)
    {
        if(u128_is_even(expo) == FALSE)
        {
            uint128 temp = u128_multiply(result, base);
        uint128 temp2[2];
        divmod128by128(temp, mod, temp2);
        result = temp2[1]; 
        }
        expo = u128_shift_right(expo);
        // printf("%llu %llu", (base*base), ((base * base) % mod));
        base = u128_multiply(base, base);
    uint128 temp3[2];
    divmod128by128(base, mod, temp3);
    base = temp3[1];
    //base = (base * base) % mod;
        // if(result > mod)
        // {
        //     result = result % mod;
        // }
        //printf("\n\n");
    }
    return result;
}*/


void divmod128by64(const uint64_t u1, const uint64_t u0, uint64_t v, uint64_t * results)
{
    // uint64_t * results = malloc(2 * sizeof(uint64_t));
    const uint64_t b = 1ll << 32;
    uint64_t un1, un0, vn1, vn0, q1, q0, un32, un21, un10, rhat, left, right;
    size_t s;

    s = nlz64(v);
    v <<= s;
    vn1 = v >> 32;
    vn0 = v & 0xffffffff;

    if (s > 0)
    {
        un32 = (u1 << s) | (u0 >> (64 - s));
        un10 = u0 << s;
    }
    else
    {
        un32 = u1;
        un10 = u0;
    }

    un1 = un10 >> 32;
    un0 = un10 & 0xffffffff;

    q1 = un32 / vn1;
    rhat = un32 % vn1;

    left = q1 * vn0;
    right = (rhat << 32) + un1;
again1:
    if ((q1 >= b) || (left > right))
    {
        --q1;
        rhat += vn1;
        if (rhat < b)
        {
            left -= vn0;
            right = (rhat << 32) | un1;
            goto again1;
        }
    }

    un21 = (un32 << 32) + (un1 - (q1 * v));

    q0 = un21 / vn1;
    rhat = un21 % vn1;

    left = q0 * vn0;
    right = (rhat << 32) | un0;
again2:
    if ((q0 >= b) || (left > right))
    {
        --q0;
        rhat += vn1;
        if (rhat < b)
        {
            left -= vn0;
            right = (rhat << 32) | un0;
            goto again2;
        }
    }

    
    results[0] = (q1 << 32) | q0;;
    results[1] = ((un21 << 32) + (un0 - (q0 * v))) >> s;
}


uint64_t div128by64(const uint64_t u1, const uint64_t u0, const uint64_t v, uint64_t q)
{
    const uint64_t b = 1ll << 32;
    uint64_t un1, un0, vn1, vn0, q1, q0, un32, un21, un10, rhat, vs, left, right;
    size_t s;

    s = nlz64(v);
    vs = v << s;
    vn1 = vs >> 32;
    vn0 = vs & 0xffffffff;


    if (s > 0)
    {
        un32 = (u1 << s) | (u0 >> (64 - s));
        un10 = u0 << s;
    }
    else
    {
        un32 = u1;
        un10 = u0;
    }


    un1 = un10 >> 32;
    un0 = un10 & 0xffffffff;

    q1 = un32 / vn1;
    rhat = un32 % vn1;

    left = q1 * vn0;
    right = (rhat << 32) | un1;

again1:
    if ((q1 >= b) || (left > right))
    {
        --q1;
        rhat += vn1;
        if (rhat < b)
        {
            left -= vn0;
            right = (rhat << 32) | un1;
            goto again1;
        }
    }

    un21 = (un32 << 32) + (un1 - (q1 * vs));

    q0 = un21 / vn1;
    rhat = un21 % vn1;

    left = q0 * vn0;
    right = (rhat << 32) | un0;
again2:
    if ((q0 >= b) || (left > right))
    {
        --q0;
        rhat += vn1;
        if (rhat < b)
        {
            left -= vn0;
            right = (rhat << 32) | un0;
            goto again2;
        }
    }

    q = (q1 << 32) | q0;
    return q;
}


void divmod128by128(uint128 M, uint128 N, uint128 *results)
{
    uint128 Q;
    uint128 R;
    uint128 one = {0x0ULL, 0x1ULL};
    if (N.hi == 0)
    {
        if (M.hi < N.lo)
        {
            uint64_t temp[2];
            divmod128by64(M.hi, M.lo, N.lo, temp);
            Q.lo = temp[0];
            R.lo = temp[1];
            Q.hi = 0;
            R.hi = 0;
            results[0] = Q;
            results[1] = R;
            return;
        }
        else
        {
            Q.hi = M.hi / N.lo;
            R.hi = M.hi % N.lo;
            uint64_t temp[2];
            divmod128by64(R.hi, M.lo, N.lo, temp);
            Q.lo = temp[0];
            R.lo = temp[1];
            R.hi = 0;
            results[0] = Q;
            results[1] = R;
            return;
        }
    }
    else
    {
        size_t n = nlz64(N.hi);

        uint128 v1;
        int i;
        for(i=0;i<n;i++)
        {
            v1 = u128_shift_left(N);
        }

        uint128 u1;
        u1 = u128_shift_right(M);

        uint128 q1;
        q1.lo = div128by64(u1.hi, u1.lo, v1.hi, q1.lo);
        q1.hi = 0;
        for(i=0;i<(63-n);i++)
        {
            q1 = u128_shift_right(q1);
        }

        if ((q1.hi | q1.lo) != 0) 
        {
            q1 = u128_subtract(q1, one);
        }

        Q.hi = q1.hi;
        Q.lo = q1.lo;
        q1 = u128_multiply(q1, N);
        R = u128_subtract(M, q1);

        if (u128_compare(R, N) >= 0)
        {
            Q = u128_add(Q, one);
            R = u128_subtract(R, N);
        }
        
        results[0] = Q;
        results[1] = R;
    }
}


uint128 mod_exponentiation(uint128 base, uint128 expo, uint128 mod)
{
    uint128 result = {0ULL, 1ULL};
    uint128 zero = {0ULL, 0ULL};
    uint128 one = {0ULL, 1ULL};
    if(u128_compare(mod, one) == 0)
    {   
        return zero;
    }
    uint128 m_minus_1 = u128_subtract(mod, one);   
    uint128 m_minus_1_squared = u128_multiply(m_minus_1, m_minus_1);
    if(u128_compare(m_minus_1_squared, mod) < 0)
    {
        printf("Warning: Mod will overflow");
    }
    //base = base % mod;
    while(u128_compare(expo,zero) != 0)
    {   
        if(u128_is_even(expo) == FALSE)
        {
            uint128 temp = u128_multiply(result, base);
            uint128 temp2[2];
            divmod128by128(temp, mod, temp2);
            result = temp2[1];
        }
        expo = u128_shift_right(expo);
        // printf("%llu %llu", (base*base), ((base * base) % mod));
        uint128 temp3 = u128_multiply(base, base);
        uint128 temp4[2];
        divmod128by128(temp3, mod, temp4);
        base = temp4[1];
        //base = (base * base) % mod;
        // if(result > mod)
        // {
        //     result = result % mod;
        // }
        //printf("\n\n");
    }   
    return result;
}



void encrypt(rsaData rsa, uint128 * encrypted)
{
  unsigned char message[7] = "Hello !";
  int i;
  for (i = 0; i<7; i++)
  {
    uint128 base = {0x0ULL, (uint64_t)message[i]};
    printf("%llu %llu    ", base);
    uint128 expo = {0ULL, rsa.pubExp};
    //divmod128by128(base, rsa.mod, temp);
    encrypted[i] = mod_exponentiation(base, expo, rsa.mod);
  }
  
}

void decrypt(rsaData rsa, uint128 ciphertext[7], char *decrypted)
{
  int i;
  //printf("\nDecrypted: ");
  for (i = 0; i < 7; i++)
  {
    //divmod128by128(base, rsa.mod, temp);
    uint128 temp = mod_exponentiation(ciphertext[i], rsa.privateExp, rsa.mod);
    printf("%llu %llu     ", temp);
    decrypted[i] = (char)temp.lo;
  }
}


/* ---------------------------- mulul64 ----------------------------- */

/* Multiply unsigned long 64-bit routine, i.e., 64 * 64 ==> 128.
Parameters u and v are multiplied and the 128-bit product is placed in
(*whi, *wlo). It is Knuth's Algorithm M from [Knu2] section 4.3.1.
Derived from muldwu.c in the Hacker's Delight collection. */

void mulul64 (uint64_t u, uint64_t v, uint64_t * whi, uint64_t * wlo)
{
  uint64_t u0, u1, v0, v1, k, t;
  uint64_t w0, w1, w2;

  u1 = u >> 32;
  u0 = u & 0xFFFFFFFF;
  v1 = v >> 32;
  v0 = v & 0xFFFFFFFF;

  t = u0 * v0;
  w0 = t & 0xFFFFFFFF;
  k = t >> 32;

  t = u1 * v0 + k;
  w1 = t & 0xFFFFFFFF;
  w2 = t >> 32;

  t = u0 * v1 + w1;
  k = t >> 32;

  *wlo = (t << 32) + w0;
  *whi = u1 * v1 + w2 + k;

  return;
}

/* ---------------------------- modul64 ----------------------------- */

uint64_t modul64 (uint64_t x, uint64_t y, uint64_t z)
{

  /* Divides (x || y) by z, for 64-bit integers x, y,
     and z, giving the remainder (modulus) as the result.
     Must have x < z (to get a 64-bit result). This is
     checked for. */

  int64 i, t;

  printf ("In modul64, x = %016llx, y = %016llx, z = %016llx\n", x, y, z);
  if (x >= z)
    {
      printf ("Bad call to modul64, must have x < z.");
      exit (1);
    }
  for (i = 1; i <= 64; i++)
    {               // Do 64 times.
      t = (int64) x >> 63;  // All 1's if x(63) = 1.
      x = (x << 1) | (y >> 63); // Shift x || y left
      y = y << 1;       // one bit.
      if ((x | t) >= z)
    {
      x = x - z;
      y = y + 1;
    }
    }
  return x;         // Quotient is y.
}

/* ---------------------------- montmul ----------------------------- */

uint64_t montmul (uint64_t abar, uint64_t bbar, uint64_t m, uint64_t mprime)
{

  uint64_t thi, tlo, tm, tmmhi, tmmlo, uhi, ulo, ov;

  printf ("\nmontmul, abar = %016llx, bbar   = %016llx\n", abar, bbar);
  printf ("            m = %016llx, mprime = %016llx\n", m, mprime);

  /* t = abar*bbar. */

  mulul64 (abar, bbar, &thi, &tlo); // t = abar*bbar.
  printf ("montmul, thi = %016llx, tlo = %016llx\n", thi, tlo);

  /* Now compute u = (t + ((t*mprime) & mask)*m) >> 64.
     The mask is fixed at 2**64-1. Because it is a 64-bit
     quantity, it suffices to compute the low-order 64
     bits of t*mprime, which means we can ignore thi. */

  tm = tlo * mprime;
  printf ("montmul, tm = %016llx\n", tm);

  mulul64 (tm, m, &tmmhi, &tmmlo);  // tmm = tm*m.
  printf ("montmul, tmmhi = %016llx, tmmlo = %016llx\n", tmmhi, tmmlo);

  ulo = tlo + tmmlo;        // Add t to tmm
  uhi = thi + tmmhi;        // (128-bit add).
  if (ulo < tlo)
    uhi = uhi + 1;      // Allow for a carry.

  // The above addition can overflow. Detect that here.

  ov = (uhi < thi) | ((uhi == thi) & (ulo < tlo));
  printf ("montmul, sum, uhi = %016llx, ulo = %016llx, ov = %lld\n", uhi, ulo,
      ov);

  ulo = uhi;            // Shift u right
  uhi = 0;          // 64 bit positions.
  printf ("montmul, ulo = %016llx\n", ulo);

// if (ov > 0 || ulo >= m)      // If u >= m,
//    ulo = ulo - m;            // subtract m from u.
  ulo = ulo - (m & -(ov | (ulo >= m))); // Alternative
  // with no branching.
  printf ("montmul, final ulo = %016llx\n", ulo);

  if (ulo >= m)
    printf ("ERROR in montmul, ulo = %016llx, m = %016llx\n", ulo, m);
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

void u128_gcd(uint128 a, uint128 b, uint128 * pu, uint128 * pv)
{
  uint128 alpha, beta;
  print(a);
  print(b);

  uint128 zero = {0x0ULL, 0x0ULL};
  uint128 u = {0x0ULL, 0x1ULL};
  uint128 v = {0x0ULL, 0x0ULL};
  alpha = a;
  beta = b;         // Note that alpha is
  // even and beta is odd.

  /* The invariant maintained from here on is:
     2a = u*2*alpha - v*beta. */

// printf("Before, a u v = %016llx %016llx %016llx\n", a, u, v);
  while(u128_compare(a, zero) > 0)
  {
    a = u128_shift_right(a);
    if(u128_is_even(u))
    {           // Delete a common
        u = u128_shift_right(u);
        v = u128_shift_right(v);       // factor of 2 in
    }
    else
    {
      /* We want to set u = (u + beta) >> 1, but
         that can overflow, so we use Dietz's method. */
        //  u = ((u ^ beta) >> 1) + (u & beta);
        uint128 temp1 = u128_xor(u,beta);
        temp1 = u128_shift_right(temp1);
        uint128 temp2 = u128_and(u, beta);
        u = u128_add(temp1, temp2);
        
        temp1 = u128_shift_right(v);
        v = u128_add(temp1,alpha);
    }
//    printf("After,  a u v = %016llx %016llx %016llx\n", a, u, v);
  }

// printf("At end,    a u v = %016llx %016llx %016llx\n", a, u, v);
  *pu = u;
  *pv = v;
  return;
}

/* ------------------------------ main ------------------------------ */


// int main2()
// {
//   char *q;
//   uint64_t a, b, m, hr, rinv, mprime, p1hi, p1lo, p1, p, abar, bbar;
//   uint64_t phi, plo;

//   // The modulus, we are computing a*b (mod m).

//   a = 0x0010cc437b67ULL;
//   b = 0x000000000005ULL;
//   m = 0x91c977a277fe00a01ULL;

//   if ((m & 1) == 0)
//     {
//       printf ("The modulus (third argument) must be odd.");
//       return 1;
//     }

//   if (a >= m || b >= m)
//     {
//       printf
//     ("The first two args must be less than the modulus (third argument).");
//       return 1;
//     }

//   printf ("a, b, m = %016llx %016llx %016llx\n", a, b, m);

//   /* The simple calculation: This computes (a*b)**4 (mod m) correctly for all a,
//      b, m < 2**64. */

//   mulul64 (a, b, &p1hi, &p1lo); // Compute a*b (mod m).
//   p1 = modul64 (p1hi, p1lo, m);
//   mulul64 (p1, p1, &p1hi, &p1lo);   // Compute (a*b)**2 (mod m).
//   p1 = modul64 (p1hi, p1lo, m);
//   mulul64 (p1, p1, &p1hi, &p1lo);   // Compute (a*b)**4 (mod m).
//   p1 = modul64 (p1hi, p1lo, m);
//   printf ("p1 = %016llx\n", p1);

//   /* The MM method uses a quantity r that is the smallest power of 2
//      that is larger than m, and hence also larger than a and b. Here we
//      deal with a variable hr that is just half of r. This is because r can
//      be as large as 2**64, which doesn't fit in one 64-bit word. So we
//      deal with hr, where 2**63 <= hr <= 1, and make the appropriate
//      adjustments wherever it is used.
//      We fix r at 2**64, and its log base 2 at 64. It doesn't hurt if
//      they are too big, it's just that some quantities (e.g., mprime) come
//      out larger than they would otherwise be. */

//   hr = 0x8000000000000000LL;

//   /* Now, for the MM method, first compute the quantities that are
//      functions of only r and m, and hence are relatively constant. These
//      quantities can be used repeatedly, without change, when raising a
//      number to a large power modulo m.
//      First use the extended GCD algorithm to compute two numbers rinv
//      and mprime, such that

//      r*rinv - m*mprime = 1

//      Reading this nodulo m, clearly r*rinv = 1 (mod m), i.e., rinv is the
//      multiplicative inverse of r modulo m. It is needed to convert the
//      result of MM back to a normal number. The other calculated number,
//      mprime, is used in the MM algorithm. */

//   xbinGCD (hr, m, &rinv, &mprime);  // xbinGCD, in effect, doubles hr.

//   /* Do a partial check of the results. It is partial because the
//      multiplications here give only the low-order half (64 bits) of the
//      products. */

//   printf ("rinv = %016llx, mprime = %016llx\n", rinv, mprime);
//   if (2 * hr * rinv - m * mprime != 1)
//     {
//       printf ("The Extended Euclidean algorithm failed.");
//       return 1;
//     }

//   /* Compute abar = a*r(mod m) and bbar = b*r(mod m). That is, abar =
//      (a << 64)%m, and bbar = (b << 64)%m. */

//   abar = modul64 (a, 0, m);
//   bbar = modul64 (b, 0, m);

//   p = montmul (abar, bbar, m, mprime);  /* Compute a*b (mod m). */
//   p = montmul (p, p, m, mprime);    /* Compute (a*b)**2 (mod m). */
//   p = montmul (p, p, m, mprime);    /* Compute (a*b)**4 (mod m). */
//   printf ("p before converting back = %016llx\n", p);

//   /* Convert p back to a normal number by p = (p*rinv)%m. */

//   mulul64 (p, rinv, &phi, &plo);
//   p = modul64 (phi, plo, m);
//   printf ("p = %016llx\n", p);
//   if (p != p1)
//     printf ("ERROR, p != p1.\n");
//   else
//     printf ("Correct (p = p1).\n");

//   return 0;
// }

// uint128 test_gcd(uint128 a, uint128 b)
// {
//     uint128 c = {0x00LL,  0x0ULL};
//     uint128 zero = {0ULL, 0ULL};
//     uint128 temp[2];
    
//     while(u128_compare(a, zero) != 0)
//     {
//         c = a;
//         divmod128by128(b, a, temp);
//         a = temp[1];
//         b = c;
//     }
//     return b;
// }


// uint128 test_gcdr(uint128 a, uint128 b)
// {
//     uint128 zero = {0ULL, 0ULL};
//     if(u128_compare(a, zero) == 0) return b;
//     uint128 temp[2];
//     divmod128by128(b, a, temp);
    
//     return test_gcdr(temp[1], a);
// }


// int main()
// {
//     //uint128 a = {0xe037d35a8b160eb7LL,  0xf11919bfef440917LL};
//     //uint128 b = {0xcab10ccaa4437b67LL,  0x11c977a277fe00a1LL};
//     uint128 a = {0ULL,  42ULL};
//     uint128 b = {0ULL,  56ULL};
//     //uint128 c = {0x0LL,  42LL};
//     //uint128 d = {0x0LL,  56LL};
//     uint128 res;
//     uint128 res_r_inv;
//     uint128 res_mprime;
    
//     // check right/left shift
//     // for(int i=0;i<16;i++)
//     // {
//     //     if(i%4 == 0)
//     //         print(res);
//     //     res = u128_shift_right(res);
//     // }
//     // print(res);
//     // print(a);
    
//     // add : GOOD
//     // res = u128_add(a, b);
  
//     // subtract : GOOD  
//     // res = u128_subtract(c,d);
    
//     // multiply : GOOD...??? 128 bit * 128 bit = 256 bit total
//     //res = u128_multiply(c, d);
    
//     // u128_gcd(c, d, &res_r_inv, &res_mprime);
    
//     res = test_gcdr(a, b);
//     print(res);
//     // print(res_r_inv);
//     // print(res_mprime);
// }



#endif