#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
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

  char* home_dir=getenv("HOME");
  char file_path[256];
  sprintf( file_path, "%s/.signEd", home_dir);
  printf( "Path to file: %s\n", file_path );

  if( access( file_path, F_OK ) == 0 ) 
  {
    printf("File found, loading keys.\n");
  } 
  else 
  {

    FILE* file_handle = fopen (file_path, "w");
    if(file_handle != NULL)
    {
      printf("Created key file %s\n",file_path );
      if( 0 != chmod( file_path, 0600 ))
      {
        printf("Could not change permission for file: %s\n", file_path);
        exit( 2 );
      }
      enc = b64_encode(public_key, 32);
      fprintf( file_handle, "%s\n", enc );
      free( enc );
      fclose( file_handle );
    }
    else
    {
      printf("Could not create key file: %s, exiting.\n",file_path);
      exit( 3 );
    }
  }
}
