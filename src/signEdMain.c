#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <libgen.h>
#include <errno.h>
#include <getopt.h>
#include <libgen.h>
#include "ed25519.h"
#include "b64.h"
#include "key_data.h"
#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"
#include "signEdMain.h"



#define OPTSTR "vsi:o:f:hac"
#define USAGE_FMT  "%s [-v] [-s] [-c] [-i inputfile] [-o outputfile] [-f signature] [-a public_key name] [-h] "
#define ERR_FOPEN_INPUT  "fopen(input, r)"
#define ERR_FOPEN_OUTPUT "fopen(output, w)"
#define ERR_DO_THE_NEEDFUL "do_the_needful blew up"
#define ERR_VERIFY "File not signed"
#define DEFAULT_PROGNAME "george"
#define BUFFER_SIZE (1 * 1024 * 1024)

extern int errno;
extern char *optarg;
extern int opterr, optind;

int dumb_global_variable = -11;
unsigned char buffer[BUFFER_SIZE]; // 1 MiB buffer

void usage(char *progname, int opt);
int  sign_file(options_t *options);
int  check_file_signature(options_t *options);

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
    char* enc;
    char command = '0';
    int expected_strings = 0;
    int opt;
    options_t options = { 0, 0x0, stdin, stdout, stdin, 0x0, 0x0 };

    opterr = 0;

    while ((opt = getopt(argc, argv, OPTSTR)) != EOF)
       switch(opt) {
           case 'i':
              if (!(options.input = fopen(optarg, "r")) ){
		 errno = ENOENT;
                 perror(ERR_FOPEN_INPUT);
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      options.input_filename = optarg;
              break;
	   case 's':
	      if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      command = 's';
              break;

	   case 'c':
              if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      command = 'c';
              break;

	   case 'a':
              if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      command = 'a';
	      expected_strings = 2;
              break;

           case 'o':
              if (!(options.output = fopen(optarg, "w")) ){
		 errno = ENOENT;
                 perror(ERR_FOPEN_OUTPUT);
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      options.output_filename = optarg;
              break;

           case 'x':
              options.flags = (uint32_t )strtoul(optarg, NULL, 16);
              break;

	   case 'f':
              if (!(options.signature_input = fopen(optarg, "r")) ){
		 errno = ENOENT;
                 perror(ERR_FOPEN_INPUT);
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
              break;


           case 'v':
              options.verbose += 1;
              break;

           case 'h':
           default:
              usage(basename(argv[0]), opt);
              /* NOTREACHED */
              break;
       }

    if(expected_strings != argc-optind)
    {
      printf("Expected number of option strings at the end: %i, but was: %i\n",
	expected_strings, argc-optind);
      exit(EXIT_FAILURE);
      /* NOTREACHED */
    }

    init_data(&options);
    if(options.verbose >= 3)
    {
      printf("mnemonic for public key:\n");
      print_mnemonic( public_key, 32 );
    }

    /*for ( ; optind < argc; optind++) 
    {
      argv[optind]
    }*/

    switch(command)
    {
      case 's':
	if (sign_file(&options) != EXIT_SUCCESS) 
        {
          exit(EXIT_FAILURE);
          /* NOTREACHED */
        }
	break;

      case 'c':
	if (check_file_signature(&options) != EXIT_SUCCESS) 
        {
          exit(EXIT_FAILURE);
          /* NOTREACHED */
        }
	break;

      case 'a':
	add_user(&options, argv[optind], argv[optind+1]);
	break;

      case '0':  /* on no command, print the public key */
        if(options.verbose >= 1) printf("Your public key:\n");
	enc = b64_encode(public_key, 32);
        printf("%s %s\n",enc, name_of_entry);
        free( enc );
	break;
    }
    
    return EXIT_SUCCESS;
}


void usage(char *progname, int opt) 
{
   fprintf(stderr, USAGE_FMT, progname?progname:DEFAULT_PROGNAME);
   exit(EXIT_FAILURE);
   /* NOTREACHED */
}

int check_file_signature(options_t *options) 
{

   if (!options) 
   {
     errno = EINVAL;
     return EXIT_FAILURE;
   }

   if (!options->input) /*|| !options->output) {*/
   {
     errno = ENOENT;
     return EXIT_FAILURE;
   }
   
   /* Copied from sign.c because hash called iterativley
    * in order to not load the complete file into ram. */
   if(options->verbose >= 2) printf("Verifying file is signed\n");

    char signature_B64[1024];
    char signature_public_key_B64[1024];
    unsigned char signed_filename[1024];
    unsigned char signature[64];
    unsigned char signature_public_key[64];
    unsigned char h[64];
    unsigned char checker[32];
    sha512_context hash;
    ge_p3 A;
    ge_p2 R;
    
    if(3 != fscanf( options->signature_input, "Signature %s\n%s\n%s\n",
      signed_filename, signature_public_key_B64,
      signature_B64 ))
    {
	printf("Signature format error.\n");
        return EXIT_FAILURE;
    }

    /* Search public key in own data. */
    if(0 != search_for_public_key(signature_public_key_B64))
    {
        printf("Unknown public key\n");
        return EXIT_FAILURE;

    }

    /* Decode B64 into binary */
    unsigned char* dec = b64_decode(signature_B64, 88);
    memcpy( (void*)signature, (void*) dec, 64 );
    free( dec );
    dec = b64_decode(signature_public_key_B64, 44);
    memcpy( (void*)signature_public_key, (void*) dec, 32 );
    free( dec );


    if (signature[63] & 224) {
        printf("Signature value error - msb are set\n");
        return EXIT_FAILURE;
    }

    if (ge_frombytes_negate_vartime(&A, signature_public_key) != 0) {
        printf("Public key error\n");
        return EXIT_FAILURE;
    }

    sha512_init(&hash);
    sha512_update(&hash, signature, 32);
    sha512_update(&hash, signature_public_key, 32);
    /*sha512_update(&hash, message, message_len);*/
    size_t bytes_read = 0;
    while( BUFFER_SIZE == (bytes_read=fread(buffer, 1, BUFFER_SIZE, options->input)))
    {
      sha512_update(&hash, buffer, BUFFER_SIZE);
      if(options->verbose >= 4) printf("sha512 full update\n");
    }
    sha512_update(&hash, buffer, bytes_read);
    if(options->verbose >= 4) printf("sha512 remainging: %li\n",bytes_read);

    sha512_final(&hash, h);
    
    sc_reduce(h);
    ge_double_scalarmult_vartime(&R, h, &A, signature + 32);
    ge_tobytes(checker, &R);

    if (!consttime_equal(checker, signature)) {
        printf("File signature does not match\n");
        return EXIT_FAILURE;
    }

    printf("File is signed\n");
    return EXIT_SUCCESS;
}

int sign_file(options_t *options) 
{

   if (!options) 
   {
     errno = EINVAL;
     return EXIT_FAILURE;
   }

   if (!options->input) /*|| !options->output) {*/
   {
     errno = ENOENT;
     return EXIT_FAILURE;
   }
   
   /* Copied from sign.c because hash called iterativley
    * in order to not load the complete file into ram. */
   if(options->verbose >= 2) printf("Signing file\n");

   size_t bytes_read = 0;

   sha512_context hash;
   unsigned char hram[64];
   unsigned char r[64];
   ge_p3 R;


   sha512_init(&hash);
   sha512_update(&hash, private_key + 32, 32);
   while( BUFFER_SIZE == (bytes_read=fread(buffer, 1, BUFFER_SIZE, options->input)))
   {
     sha512_update(&hash, buffer, BUFFER_SIZE);
     if(options->verbose >= 4) printf("sha512 full update\n");
   }
   sha512_update(&hash, buffer, bytes_read);
   if(options->verbose >= 4) printf("sha512 remainging: %li\n",bytes_read);
   sha512_final(&hash, r);

   sc_reduce(r);
   ge_scalarmult_base(&R, r);
   ge_p3_tobytes(signature, &R);

   sha512_init(&hash);
   sha512_update(&hash, signature, 32);
   sha512_update(&hash, public_key, 32);
   /*sha512_update(&hash, message, message_len);*/
   rewind(options->input);
   while( BUFFER_SIZE == (bytes_read=fread(buffer, 1, BUFFER_SIZE, options->input)))
   {
     sha512_update(&hash, buffer, BUFFER_SIZE);
     if(options->verbose >= 4) printf("sha512 full update\n");
   }
   sha512_update(&hash, buffer, bytes_read);
   if(options->verbose >= 4) printf("sha512 remainging: %li\n",bytes_read);

   sha512_final(&hash, hram);

   sc_reduce(hram);
   sc_muladd(signature + 32, hram, private_key, r);
    
   printf("Signature %s\n",basename(options->input_filename));
   char* enc = b64_encode(public_key, 32);
   printf("%s\n",enc);
   free( enc );
   enc = b64_encode(signature, 64);
   printf("%s\n",enc);
   free( enc );

   if(options->verbose >= 2) printf("Done\n");
   return EXIT_SUCCESS;
}
