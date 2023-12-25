#include <stdio.h>

static inline unsigned int crc32b(unsigned char *message) 
{
   int i, j;
   unsigned int byte, crc, mask;

   i = 0;
   crc = 0xFFFFFFFF;
   while (message[i] != 0) {
      byte = message[i];            // Get next byte.
      crc = crc ^ byte;
      for (j = 7; j >= 0; j--) {    // Do eight times.
         mask = -(crc & 1);
         crc = (crc >> 1) ^ (0xEDB88320 & mask);
      }
      i = i + 1;
   }
   return ~crc;
}

// Function that convert Decimal to binary 
int decToBinary(int n) 
{ 
    // Size of an integer is assumed to be 32 bits 
    for (int i = 31; i >= 0; i--) { 
        int k = n >> i; // right shift 
        if (k & 1) // helps us know the state of first bit 
              printf("1"); 
        else printf("0"); 
    } 
} 

int main() {
    char *message = "1.1.1.15300210.30.2.180";
    int hashed = crc32b(message);
    decToBinary(hashed);
    return 0;
}