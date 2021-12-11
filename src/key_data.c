#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include "ed25519.h"
#include "b64.h"
#include "signEdMain.h"

/* File format: each line is either:
 *
 * Personality name-of-personality
 * public_key
 * private_key
 *
 * or
 *
 * User name-of-user
 * public_key
 *
 * */

unsigned char seed[32];
unsigned char public_key[32];
unsigned char private_key[64];
unsigned char signature[64];
char name_of_entry[1024];
char type_of_entry[12];

static char file_path[256];


void init_data(options_t* opt)
{
  char* home_dir=getenv("HOME");
  sprintf( file_path, "%s/.signEd", home_dir);
  if(opt->verbose >= 2) printf( "Path to file: %s\n", file_path );

  if( access( file_path, F_OK ) == 0 ) 
  {
    if(opt->verbose >= 2) printf("File found, loading keys.\n");
    char public_key_base64[45];
    char private_key_base64[89];
        FILE* file_handle = fopen (file_path, "r");
    if( 4 != fscanf( file_handle, "%s %s\n%s\n%s\n", 
      type_of_entry,
      name_of_entry,
      public_key_base64, 
      private_key_base64 ))
    {
      printf("Could not find default personality at start of key file");
      exit( 5 );
    }
    if(opt->verbose >= 2) 
      printf("Loaded public key: %s \nLoaded private key: %s\n",
        public_key_base64, private_key_base64);
    fclose( file_handle );
    unsigned char* dec = b64_decode(public_key_base64, 44);
    memcpy( (void*)public_key, (void*) dec, 32 );
    free( dec );
    dec = b64_decode(private_key_base64, 88);
    memcpy( (void*)private_key, (void*) dec, 64 );
    free( dec );
  } 
  else 
  {
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
    //phex( public_key, 32 );

    if(opt->verbose >= 2) printf("Generated private key: \n");
    enc = b64_encode(private_key, 64);
    printf("%s\n",enc);
    free( enc );
    //phex( public_key, 64 );


    FILE* file_handle = fopen (file_path, "w");
    if(file_handle != NULL)
    {
      if(opt->verbose >= 2) printf("Created key file %s\n",file_path );
      if( 0 != chmod( file_path, 0600 ))
      {
        printf("Could not change permission for file: %s\n", file_path);
        exit( 2 );
      }

      fprintf( file_handle, "Personality " );
      char hostname[HOST_NAME_MAX];
      char username[LOGIN_NAME_MAX];
      gethostname(hostname, HOST_NAME_MAX);
      getlogin_r(username, LOGIN_NAME_MAX);
      fprintf( file_handle, "%s@%s\n", username, hostname );
      enc = b64_encode(public_key, 32);
      fprintf( file_handle, "%s\n", enc );
      free( enc );
      enc = b64_encode(private_key, 64);
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

int add_user(options_t* opt, char* public_key, char* username )
{
    if(opt->verbose >= 2) printf("Adding user %s, public key %s\n",
		    username, public_key);
    FILE* file_handle = fopen (file_path, "a");
    if(file_handle != NULL)
    {
      if(opt->verbose >= 2) printf("Appending to key file %s\n",file_path );
      if( 0 != chmod( file_path, 0600 ))
      {
        printf("Could not change permission for file: %s\n", file_path);
        exit( 2 );
      }

      fprintf( file_handle, "User %s\n", username );
      fprintf( file_handle, "%s\n", public_key );

      fclose( file_handle );
    }
    else
    {
      return EXIT_FAILURE;
    }
      
    if(opt->verbose >= 2) printf("Adding user finished\n" );
   return EXIT_SUCCESS;
}

int search_for_public_key(char* signature_public_key)
{
   char command[24];
   char username[1024];
   char public_key_b64[1024];
   char private_key_b64[1024];

   FILE* file_handle = fopen (file_path, "r");

   /* First check the entry type */
   while(2 == fscanf(file_handle, "%s %s\n", command, username ))
   {
     if(0 == strcmp("User",command))
     {
       if(1 != fscanf(file_handle, "%s\n", public_key_b64 ))
       {
         printf("Key file error");
         return EXIT_FAILURE;
       }
     }
     else if(0 == strcmp("Personality",command))
     {
       if( 2 !=fscanf(file_handle, "%s\n%s\n", public_key_b64, 
	   private_key_b64 ))
       {
         printf("Key file error");
         return EXIT_FAILURE;
       }
     }
     else
     {
       printf("Key file error");
       return EXIT_FAILURE;
     }

     if(0 == strcmp(public_key_b64,signature_public_key))
     {
       return EXIT_SUCCESS;
     }
   }

   printf("Key not found");
   return EXIT_FAILURE;
}

void strip_extension(char *fname)
{
    char *end = fname + strlen(fname);

    while (end > fname && *end != '.') {
        --end;
    }

    if (end > fname) {
        *end = '\0';
    }
}

int remove_signature_from_file(options_t* options)
{
    char signed_filename[1024];
    char signature_B64[1024];
    char signature_public_key_B64[1024];

    if(3 != fscanf( options->signature_input, "Signature %s\n%s\n%s\n",
      signed_filename, signature_public_key_B64,
      signature_B64 ))
    {
	printf("Signature format error.\n");
        return EXIT_FAILURE;
    }

    char new_filename[1024];
    strcpy(new_filename, options->input_filename);
    strip_extension(new_filename);

    /* Copy into new file. */
    FILE* p_new_file = fopen( new_filename, "w" );
    char buffer[1*1024*1024];
    size_t bytes;
    while (0 < (bytes = fread(buffer, 1, sizeof(buffer), options->input)))
      fwrite(buffer, 1, bytes, p_new_file);
    fclose( p_new_file );

    return EXIT_SUCCESS;
}
