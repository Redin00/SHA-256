#include<stdint.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"utils.h"

// Costants used for the conversion. These costants are selected by the first 32 bits of the fractional parts of the cube roots of the first 64 prime numbers
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Declaring functions
uint8_t* paddingMessage(uint8_t* message, size_t lenght, size_t* paddedLenght);

void processingBlock(uint8_t* block, uint32_t* hashValues);

void sha256(uint8_t* message, size_t lenght, uint8_t hash[32]);

char *read_string();

// Main entry point
int main(){

    uint8_t hashContainer[32];
    
    char *inputString = read_string();

    sha256((uint8_t*)inputString, (size_t) strlen(inputString), hashContainer);

    for(int i=0; i<32; i++){
        printf("%02x", hashContainer[i]);
    }

    free(inputString);

    return 0;
}


// ######### SHA 256 FUNCTIONS #########

// Function for padding the message as stated by the SHA-256 standard.
uint8_t* paddingMessage(uint8_t* message, size_t lenght, size_t* paddedLenght){

    // Padding the message by adding a bit '1' followed by zero bits to get a message with a fixed size (read the documentation that provides a more specific explanation) 

    size_t newLenght = lenght + 1;  // Adding 1 byte for 0x80 value, because in SHA-256 padding involves adding a "1 bit" followed by zero bits.
    while(newLenght % 64 != 56){
        newLenght++;
    }

    *paddedLenght = newLenght + 8;  // Adding 8 bytes of lenght for the 64 big endian.

    // Creating the variable (unsigned char = uint8_t) for containing the padded message and allocating the necessary size.
    uint8_t* paddedMessage = (uint8_t*)malloc(*paddedLenght);
    if (!paddedMessage) {
        perror("Failed to allocate memory!");
        exit(1);
    }

    // Copying the original message to the new padded message. We're using the memcpy function to alloc the exact amount of memory needed.
    memcpy(paddedMessage, message, lenght);
    paddedMessage[lenght] = 0x80;   // Adding the '1' bit at the end of the ORIGINAL message, because 0x80 is a value of 8 bit with the first bit at '1'
    memset(paddedMessage + lenght + 1, 0, newLenght - (lenght + 1) - 8);    // Filling with zeros

    // Lenght of the original message expressed with a 64 big endian and in bits.
    uint64_t BigEndianLenght = lenght * 8;  // We multiply for 8 because we want the lenght in BITS and not in bytes 

    // Appending the 64-bit big endian
    for(int i=0; i<8; i++){
        paddedMessage[*paddedLenght - 1 - i] = (BigEndianLenght >> (8 * i)) & 0xff;     // & 0xff gives the last 8bit (0xff = 255, so a byte with all bit at '1'). It is essentially used for returning the bits.
    }

    return paddedMessage;

}



void processingBlock(uint8_t* block, uint32_t* hashValues){

    // Function for processing blocks. This process is a bit complex. If you want to understand it more, read the documentation provided by National Institute of Standards and Technology on Secure Hash Algorithms: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf

    uint32_t a, b, c, d, e, f, g, h;       // The eight variables that will be used for hashing.
    
    uint32_t W[64];    // 512 bit block.

    for(int i=0, j = 0; i<16; i++, j+= 4){
        W[i] = (block[j] << 24) | (block[j + 1] << 16) | (block[j + 2] << 8) | block[j + 3]; // "<< 1" at the last block will be redundant.
    }

    for(int i=16; i<64; i++){
        W[i] = sigma1(W[i - 2]) + W[i - 7] + sigma0(W[i - 15]) + W[i - 16];
    }

    // Working with the variables and using a loop with maths operations.
    a = hashValues[0];
    b = hashValues[1];
    c = hashValues[2];
    d = hashValues[3];
    e = hashValues[4];
    f = hashValues[5];
    g = hashValues[6];
    h = hashValues[7];

    for(int i=0; i<64; i++){
        uint32_t T1 = h + SigmaCapital1(e) + Ch(e, f, g) + K[i] + W[i];
        uint32_t T2 = SigmaCapital0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    hashValues[0] += a;
    hashValues[1] += b;
    hashValues[2] += c;
    hashValues[3] += d;
    hashValues[4] += e;
    hashValues[5] += f;
    hashValues[6] += g;
    hashValues[7] += h;

}

void sha256(uint8_t* message, size_t lenght, uint8_t hash[32]){
    
    size_t paddedLenght;    

    // Initial hash values used for the conversion, retrieved by the first 32 bit of the decimal part of the square root of the first eight natural prime numbers.
    uint32_t H[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    };

    // Padding the message
    uint8_t* paddedMessage = paddingMessage(message, lenght, &paddedLenght);        // By passing the address of paddedLenght, we can modify it directly inside the function paddingMessage.

    // Splitting the message into N blocks. 
    /*
     * In SHA-256, the message is divided into N blocks of 512 bit. The block can also  be expressed as sixteen 32-bit words. 
    */
    for(size_t i=0; i<paddedLenght; i+=64){        // For loop that repeats until the lenght of the padded message is surpassed. The padded message is always divisible by 64, so this means that the for loop executes for N blocks.
        processingBlock(paddedMessage + i, H);
    }

    
    // Final operation 
    for(int i=0; i<8; i++){

        hash[i * 4] = (H[i] >> 24 ) & 0xff;     // "& 0xff" returns the bits, because 0xff is a sequence of bit with all '1'.
        hash[i * 4 + 1] = (H[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (H[i] >> 8) & 0xff;
        hash[i * 4 + 3] = (H[i]) & 0xff;
    }

    // Freeing memory.
    free(paddedMessage);
    
}


// Getting the input and allocating the memory dynamically (Code taken by StackOverflow).
char *read_string() {   
    char *big = NULL, *old_big;
    char s[11] = {0};
    int len = 0, old_len;
  
    do {
      old_len = len;
      old_big = big;
      scanf("%10[^\n]", s);
      if (!(big = realloc(big, (len += strlen(s)) + 1))) {
        free(old_big);
        fprintf(stderr, "Out of memory!\n");
        return NULL;
      }
      strcpy(big + old_len, s);
    } while (len - old_len == 10);
    return big;
  }