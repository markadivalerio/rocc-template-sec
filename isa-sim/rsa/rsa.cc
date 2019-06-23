#include "rocc.h"
#include "mmu.h"
#include "extension.h"
#include "rsa.h"

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
}

uint64_t leftmostbit = 0x8000000000000000ULL;
uint64_t rightmostbit = 0x0000000000000001ULL;

bool u128_is_even(uint128 num)
{
	if(num.lo & rightmostbit == 0)
		return true;
	return false;
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
// 	uint128 temp_u = {0x0ULL, 0x1ULL};
// 	uint128 temp_v = {0x0ULL, 0x0ULL};
// 	uint128 alpha = a;
// 	uint128 beta = b;

// 	uint128 result = {0x0ULL, 0x1ULL};

// 	while(a.hi > 0ULL || a.low > 0ULL)
// 	{
// 		a = u128_shift_right(a);
// 		temp_v = u128_shift_right(temp_v);
// 		if(~u128_is_even(temp_u))
// 		{
// 			temp_u = u128_shift_right(temp_u);
// 		}
// 		else
// 		{
// 			temp_v = u128_add(temp_u, alpha);
			
// 			temp_u = u128_xor(temp_u, beta);
// 			temp_u = u128_shift_right(temp_u);

// 		}
// 	}
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
        printf("\n\n");
    }
    return result;
}

uint64_t * encrypt(rsaData rsa, unsigned char * message)
{
	uint64_t * encrypted;
	int i;
	uint64_t base = 0ULL;
	uint64_t expo = rsa.pubExp;
	uint64_t mod = rsa.mod.lo;
	for (i = 0; message[i] != '\0'; i++)
	{
		base = (uint64_t)message[i];
		encrypted[i] = mod_exponentiation(base, expo, mod);
	}
	return encrypted;
}

unsigned char * decrypt(rsaData rsa, uint64_t * cipher)
{
	unsigned char * decrypted='';
	int i;
	uint64_t base = 0ULL;
	uint64_t expo = rsa.privateExp;
	uint64_t mod = rsa.mod.lo;
	for (i = 0; cipher[i] != '\0'; i++)
	{
		uint64_t temp = mod_exponentiation(cipher[i], expo, mod);
		decrypted[i] = (unsigned char) temp;
	}
	decrypted[i+1] = '\0';
	return decrypted;
}