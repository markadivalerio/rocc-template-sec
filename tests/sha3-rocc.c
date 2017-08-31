//see LICENSE for license
// The following is a RISC-V program to test the functionality of the
// sha3 RoCC accelerator.
// Compile with riscv-unknown-elf-gcc sha3-rocc.c
// Run with spike --extension=sha3 pk a.out

#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include "sha3.h"

int main() {

    // BASIC TEST 1 - 150 zero bytes

    // Setup some test data
    unsigned int ilen = 150;
    unsigned char input[150] = "\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000\000";
    unsigned char output[SHA3_256_DIGEST_SIZE];
    int dummy_result;

    asm volatile ("fence");
    // Invoke the acclerator and check responses

    // setup accelerator with addresses of input and output
    //              opcode rd rs1          rs2          funct   
    // asm volatile ("custom0 0, %[msg_addr], %[hash_addr], 0" : : [msg_addr]"r"(&input), [hash_addr]"r"(&output));
    ROCC_INSTRUCTION(0, dummy_result, &input, &output, 0);

    // YOUR CODE HERE: Call the ROCC instructon to set length and compute hash

    asm volatile ("fence");

    // Check result
    int i = 0;
    unsigned char result[SHA3_256_DIGEST_SIZE] =
        {221,204,157,217,67,211,86,31,54,168,44,245,97,194,193,26,234,42,135,166,66,134,39,174,184,61,3,149,137,42,57,238};
    for(i = 0; i < SHA3_256_DIGEST_SIZE; i++){
        printf("output[%d]:%d ==? results[%d]:%d \n",i,output[i],i,result[i]);
        assert(output[i]==result[i]);
    }
    printf("success!\n");
    return 0;
}
