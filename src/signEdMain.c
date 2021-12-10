#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include "ed25519.h"
#include "b64.h"
#include "key_data.h"

void phex(unsigned char* str, int len)
{
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}

char* mnemonic1[] = { "the house", "the cat", "superman" };
size_t mnemonic1_length = sizeof(mnemonic1)/sizeof(mnemonic1[0]);
char* mnemonic2[] = { "eats", "crashes", "fries", "delivers" };
size_t mnemonic2_length = sizeof(mnemonic2)/sizeof(mnemonic2[0]);
char* mnemonic3[] = { "my neighbour", "a smelly pie", "a chandelier" };
size_t mnemonic3_length = sizeof(mnemonic3)/sizeof(mnemonic3[0]);
char* mnemonic4[] = { "in the face", "hidden from public", "and said hi" };
size_t mnemonic4_length = sizeof(mnemonic4)/sizeof(mnemonic4[0]);

void print_mnemonic_part( uint64_t** pvalue, 
  int* length, char* mnemonic[], size_t mnemonic_length)
{
  int index = **pvalue % mnemonic_length;
  printf("%s ", mnemonic[ index ] );
  *pvalue += 1;
  *length -= 8;
}

void print_mnemonic( unsigned char* data, int length )
{
  uint64_t* pvalue = (uint64_t*)data;
  print_mnemonic_part( &pvalue, &length, mnemonic1, mnemonic1_length);
  print_mnemonic_part( &pvalue, &length, mnemonic2, mnemonic2_length);
  print_mnemonic_part( &pvalue, &length, mnemonic3, mnemonic3_length);
  print_mnemonic_part( &pvalue, &length, mnemonic4, mnemonic4_length);
  printf("\n");
}


int main(int argc, char* argv[])
{
  init_data();
  printf("mnemonic for public key:\n");
  print_mnemonic( public_key, 32 );
}
