#include <stdio.h>
#include <stdlib.h>
#include "ed25519.h"
#include "b64.h"

void phex(unsigned char* str, int len)
{
    unsigned char i;
    for (i = 0; i < len; ++i)
        printf("%.2x", str[i]);
    printf("\n");
}


unsigned char seed[32];
unsigned char public_key[32];
unsigned char private_key[64];

int main(int argc, char* argv[])
{
  printf("Hello world\n");
  int result = ed25519_create_seed( seed );
  if(result != 0)
  {
    printf("Could not create random seed.");
    exit( 1 );
  }
  ed25519_create_keypair(public_key, private_key,
                         seed);

  printf("Generated public key: \n");
  char *enc = b64_encode(public_key, 32);
  printf("%s\n",enc);
  free( enc );
  phex( public_key, 32 );

  printf("Generated private key: \n");
  enc = b64_encode(public_key, 64);
  printf("%s\n",enc);
  free( enc );
  phex( public_key, 64 );

}
