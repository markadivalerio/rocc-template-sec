//see LICENSE for license
// The following is a RISC-V program to test the functionality of the
// rsa RoCC accelerator.
// Compile with riscv-unknown-elf-gcc rsa-rocc.c
// Run with spike --extension=rsa pk a.out

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "rsa.h"
#include <stdint.h>

int main() {
/* Private-Key: (128 bit)                                                                                                                                         */
/* modulus: */
/*    00:e0:37:d3:5a:8b:16:0e:b7:f1:19:19:bf:ef:44: */
/*    09:17 */
/* publicExponent: 65537 (0x10001) */
/* privateExponent: */
/*    00:ca:b1:0c:ca:a4:43:7b:67:11:c9:77:a2:77:fe: */
/*    00:a1 */
/* prime1: 18125493163625818823 (0xfb8aafffd4b02ac7) */
/* prime2: 16442969659062640433 (0xe43129c94cf45f31) */
/* exponent1: 5189261458857000451 (0x4803f5cd8dcbfe03) */
/* exponent2: 12850891953204883393 (0xb2578a24fdb3efc1) */
/* coefficient: 10155582946292377246 (0x8cefe0e210c5a69e) */

    //DO NOT MODIFY
    uint128 modulus = {0xe037d35a8b160eb7LL,  0xf11919bfef440917LL};
    uint128 privateExp = {0x00cab10ccaa4437b67LL,  0x11c977a277fe00a1LL};
    uint64_t pubExp = 65537;
    const char plaintext[] = "Hello !";
    uint128 ciphertext;
    uint128 decrypted;
    //END DO NOT MODIFY
    int dummy_result;

    uint128 mymod = {0xe037d35a8b160eb7LL, 0xf11919bfef440917LL};

    uint64_t initCycle, duration;
    initCycle = rdcycle();
    asm volatile ("fence"); //NOTE that fences are only needed if your accelerator accesses memory
    /* YOUR CODE HERE: Invoke your RSA acclerator, write the encrypted output of plaintext to ciphertext */
    // rd, rs1, and rs2 are data
    // rd_n, rs_1, and rs2_n are the register numbers to use
    //ROCC_INSTRUCTION_R_R_R(X, rd, rs1, rs2, funct);

/*    rsaData rsa = {
        {0ULL, 0xfb8aafffd4b02ac7ULL}, //prime1
        {0ULL, 0xe43129c94cf45f31ULL}, //prime2
        65537UL, //pubExp
        {0x00cab10ccaa4437b67ULL,  0x11c977a277fe00a1ULL}, //privateExp
        {0ULL, 0xcbfe03ULL} //mod
    };*/
    rsaData rsa = {
	{0ULL, 61ULL}, 	//prime1
        {0ULL, 53ULL}, 	//prime2
        17UL, 		//pubExp
        {0x0ULL, 2753ULL}, //privateExp
        {0ULL, 3233ULL} //mod
    };
    uint64_t encrypted[7];
    encrypt(rsa, plaintext, encrypted);
    asm volatile ("fence");

    //DO NOT MODIFY
    duration = rdcycle() - initCycle;
    printf("RSA Encryption took %llu cycles!\n", duration);
    initCycle = rdcycle();
    //END DO NOT MODIFY

    /* YOUR CODE HERE: Invoke your RSA acclerator, write the decrypted output of ciphertext to decrypted */
    unsigned char decrypted2[7];
    decrypt(rsa, encrypted, decrypted2);
    asm volatile ("fence");

    //DO NOT MODIFY
    duration = rdcycle() - initCycle;
    printf("RSA Decryption took %llu cycles!\n", duration);

    //char *decrypted_text = (char*)&decrypted;
    printf("decrypted=%s\n", decrypted2);
    assert(strcmp(plaintext, decrypted2) == 0);
    //printf("decrypted=%s\n", decrypted_text);
    //assert(strcmp(plaintext, decrypted_text) == 0);
}
