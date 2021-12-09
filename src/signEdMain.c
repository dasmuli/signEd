#include <stdio.h>
#include <stdlib.h>
#include "ed25519.h"

unsigned char seed[32];

int main(int argc, char* argv[])
{
  printf("Hello world\n");
  int result = ed25519_create_seed( seed );
  if(result != 0)
  {
    printf("Could not create random seed.");
    exit( 1 );
  }
}
