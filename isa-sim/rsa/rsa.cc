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

uint64_t leftmostbit = 0x8000000000000000ULL;
uint64_t rightmostbit = 0x0000000000000001ULL;

int rsa_t::u128_is_even(uint128 num)
{
  if(num.lo & rightmostbit == 0)
    return TRUE;
  return FALSE;
}

uint128 rsa_t::u128_shift_right(uint128 num)
{
    num.lo >>= 1;
    if(num.hi & rightmostbit == 1)
        num.lo = num.lo | leftmostbit;
    num.hi >>= 1;
    return num;
}

uint128 rsa_t::u128_shift_left(uint128 num)
{
    num.hi <<= 1;
    if(num.lo & leftmostbit != 0)
        num.hi |= rightmostbit;
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

int rsa_t::u128_compare(uint128 a, uint128 b)
{
  return  (((a.hi > b.hi) || ((a.hi == b.hi) && (a.lo > b.lo))) ? 1 : 0) 
     -  (((a.hi < b.hi) || ((a.hi == b.hi) && (a.lo < b.lo))) ? 1 : 0);
}


size_t rsa_t::nlz64(uint64_t N)
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

size_t rsa_t::ntz64(uint64_t N)
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

size_t rsa_t::nlz128(uint128 N) // Number of Leading Zeros
{
    return (N.hi == 0) ? nlz64(N.lo) + 64 : nlz64(N.hi);
}

size_t rsa_t::ntz128(uint128 N) // number of trailing zeros
{
    return (N.lo == 0) ? ntz64(N.hi) + 64 : ntz64(N.lo);
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
    // TODO detect overflow?
    return result;
}

uint128 rsa_t::u128_multiply(uint128 a, uint128 b)
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

uint128 rsa_t::big_mod_w_subtract(uint128 numerator, uint128 denominator)
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

uint128 rsa_t::u128_hybrid_mod(uint128 base, uint128 expo, uint128 mod)
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

uint64_t rsa_t::mod_exponentiation(uint64_t base, uint64_t expo, uint64_t mod)
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
        printf("\n\n");
    }
    return result;
}

uint128 * rsa_t::bindivmod128(uint128 M, uint128 N)
{
    uint128 results[2];
    uint128 Q;
    uint128 R;
    Q.hi = Q.lo = 0;
    R.hi = R.lo = 0;
    size_t Shift = nlz128(N) - nlz128(M);
    int i;
    for(i=0;i<Shift;i--)
    {
        N = u128_shift_left(N);
    }

    do
    {
        Q = u128_shift_left(Q);
        if(u128_compare(M, N) >= 0)
        {
            // sub128(M, N, M);
            M = u128_subtract(M, N);
            Q.lo |= 1;
        }

        N = u128_shift_right(N);
    }while(Shift-- != 0);

    R = M;
    results[0] = Q;
    results[1] = R;
    return results;
}


void rsa_t::divmod128by64(const uint64_t u1, const uint64_t u0, uint64_t v, uint64_t * results)
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


uint64_t rsa_t::div128by64(const uint64_t u1, const uint64_t u0, const uint64_t v, uint64_t q)
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


void rsa_t::divmod128by128(uint128 M, uint128 N, uint128 *results)
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
            // dec128(q1, q1);
            q1 = u128_subtract(q1, one);
        }

        Q.hi = q1.hi;
        Q.lo = q1.lo;
        // mult128(q1, N, q1);
        q1 = u128_multiply(q1, N);
        // sub128(M, q1, R);
        R = u128_subtract(M, q1);

        if (u128_compare(R, N) >= 0)
        {
            // inc128(Q, Q);
            Q = u128_add(Q, one);
            R = u128_subtract(R, N);
        }
        
        results[0] = Q;
        results[1] = R;
    }
}




void rsa_t::encrypt(rsaData rsa, uint128 * plaintext, uint128 * encrypted)
{
  int i;
  for (i = 0; i < 7; i++)
  {
      uint128 temp[2];
      uint128 tempPower = {0ULL, rsa.pubExp};
    //   printf("%c  ", plaintext[i]);
    //   printf("%llu %llu  ", tempPower);
    //   uint128 mToPowerE = u128_power(plaintext[i], tempPower);
    //   printf("%llu %llu  ", mToPowerE);
      divmod128by128(plaintext[i], rsa.mod, temp);
      encrypted[i] = temp[1];
  }
}

void rsa_t::decrypt(rsaData rsa, uint128 * cipher, uint128 * decrypted)
{
  int i;
  for (i = 0; i < 7; i++)
  {
      uint128 temp[2];
      divmod128by128(cipher[i], rsa.privateExp, temp);
      decrypted[i] = temp[1];
  }
}

// int main()
// {
    
//     rsaData rsa = {
//         {0ULL, 7ULL}, //prime1
//         {0ULL, 3ULL}, //prime2
//         1UL,//pub
//         {0x0ULL,  2ULL}, //private
//         {0x0ULL, 21LL}
//     };
//     unsigned char plaintext[] = "Hello !";
//     uint128 encrypted[7];
//     uint128 decrypted[7];
//     encrypt(rsa, plaintext, encrypted);
//     int i;
//     for(i=0;i<7;i++)
//     {
//         printf("%llu %llu   ", encrypted[i]);
//     }
    
//     decrypt(rsa, encrypted, decrypted);
//     for(i=0;i<7;i++)
//     {
//         printf("%llu.%llu  ", decrypted[i]);
//     }
//     for(i=0;i<7;i++)
//     {
//         printf("%c ", (char) decrypted[i].lo);
//     }
    
//     // printf("Hello World\n");
//     // uint128 m = {0x0ULL, 240ULL}; //m % n,  (m^e)mod(n)
//     // uint128 n = {0x0ULL, 400ULL}; //28EC8685211249B22
//     // uint128 quotient =  {0x0ULL, 0ULL};
//     // uint128 remain =  {0x0ULL, 0ULL};
//     // uint128 results[2];
//     // uint64_t res;
//     // uint64_t q;
//     // uint64_t r;
//     // uint64_t res2[2];
//     // // divmod128by64(m.hi, m.lo, n.lo, res2); // divmod128by64
//     // // printf("%llu", res);
//     // // printf("%llu %llu", res2[0], res2[1]);
//     // divmod128by128(m, n, results);
//     // printf("%llu %llu with %llu %llu", results[0], results[1]);
//     // uint128 results[2] = divmod128by128(m, n, quotient, remain);
//     // printf("%llu %llu with %llu %llu", results[0], results[1]);
    
//     // divmod128by128(m, n, quotient, remain);
//     // printf("%llu %llu", remain.hi, remain.lo);
    
//     return 0;
// }
