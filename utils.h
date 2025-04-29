#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>

// ------- Header for particular math functions and bitwise operations of SHA-256 -------  

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ (~x & z);
}

uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){
    return (x & y) ^ (x & z) ^ (y & z);
}

// Rotate left (circular left shift) operation
uint32_t ROTL(uint32_t x, uint32_t n){
    return (x << n) | (x >> (32 - n));    // Note: 32 equals to the number of bits in a word. SHA-256 uses 32bits for each word.
}

// Rotate right (circular right shift) operation
uint32_t ROTR(uint32_t x, uint32_t n){
    return (x >> n) | (x << (32 - n));    // Note: 32 equals to the number of bits in a word. SHA-256 uses 32 bits for each word.
}

// Right shift operation 
uint32_t SHR(uint32_t x, uint32_t n){
    return x >> n;
}

// Sigma function 0
uint32_t sigma0(uint32_t x){
    return ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3);
}

// Sigma function 1
uint32_t sigma1(uint32_t x){
    return ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10);
}

// Sigma capital 0
uint32_t SigmaCapital0(uint32_t x) {
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

// Sigma capital 1
uint32_t SigmaCapital1(uint32_t x) {
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}