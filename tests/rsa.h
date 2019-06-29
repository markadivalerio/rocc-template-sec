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

void encrypt(rsaData rsa, uint128 * encrypted);
void decrypt(rsaData rsa, uint128 ciphertext[7], char * decrypted);

uint64_t leftmostbit =  0x8000000000000000ULL;
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
    if(num.lo >> 63)
        num.hi = num.hi | rightmostbit;
    num.lo <<= 1;
    return num;
}

uint128 shiftright128(uint128 N, unsigned S)
{
	uint128 res;
	uint64_t M1, M2;
	S &= 127;

	M1 = ((((S + 127) | S) & 64) >> 6) - 1llu;
	M2 = (S >> 6) - 1llu;
	S &= 63;
	res.lo = (N.hi >> S) & (~M2);
	res.hi = (N.hi >> S) & M2;
	res.lo |= ((N.lo >> S) | ((N.hi << (64 - S)) & M1)) & M2;
	return res;
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
        printf("WARNING: subtraction underflow");
    }

    result.hi = left.hi - right.hi;
    result.lo = left.lo - right.lo;
    if(result.lo > left.lo)
        result.hi -= 1;
    return result;
}

uint128 sub128(uint128 N, uint128 M)
{
	uint128 res;
	res.lo = N.lo - M.lo;
	uint64_t C = (((res.lo & M.lo) & 1) + (M.lo >> 1) + (res.lo >> 1)) >> 63;
	res.hi = N.hi - (M.hi + C);
	return res;
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
    uint128 m_minus_1 = sub128(mod, one);   
    uint128 m_minus_1_squared = mult128(m_minus_1, m_minus_1);
    if(u128_compare(m_minus_1_squared, mod) < 0)
    {
        printf("Warning: Mod will overflow");
    }
    //base = base % mod;
    while(u128_compare(expo,zero) != 0)
    {   
        if(u128_is_even(expo) == FALSE)
        {
            uint128 temp = mult128(result, base);
            uint128 temp2[2];
            divmod128by128(temp, mod, temp2);
            result = temp2[1];
        }
        expo = u128_shift_right(expo);
        // printf("%llu %llu", (base*base), ((base * base) % mod));
        uint128 temp3 = mult128(base, base);
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


#endif
