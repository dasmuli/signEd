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
#include <sys/random.h>
#include "ed25519.h"
#include "b64.h"
#include "key_data.h"
#include "ed25519.h"
#include "sha512.h"
#include "ge.h"
#include "sc.h"
#include "aes.h"
#include "signEdMain.h"



#define OPTSTR "vsi:o:f:hacxmzu:n:p:wle"
#define USAGE_FMT  "%s [-v] [-s] [-c] [-i inputfile] [-o outputfile] [-f signaturefile] [-x] [-m] [-z] [-u] [-a public_key name] [-n personality] [-p personality] [-l] [-w] [-e] [-h] "
#define ERR_FOPEN_INPUT  "fopen(input, r)"
#define ERR_FOPEN_OUTPUT "fopen(output, w)"
#define ERR_DO_THE_NEEDFUL "do_the_needful blew up"
#define ERR_VERIFY "File not signed"
#define DEFAULT_PROGNAME "george"
#define BUFFER_SIZE (1 * 1024 * 1024)

extern int errno;
extern char *optarg;
extern int opterr, optind;

unsigned char buffer[BUFFER_SIZE]; // 1 MiB buffer
unsigned char aes_iv[AES_BLOCKLEN];

void usage(char *progname, int opt);
int sign_file(options_t *options);
int check_file_signature(options_t *options);
int show_shared_zecret(options_t *options);
int calculate_shared_key(options_t* options, char* user_key_found);

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
    options_t options = { 0, false, 0x0, stdin, stdout, stdin, 0x0, 0x0,
        {}, 0, 0x0, 0 };

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
	      if(options.signature_input == stdin)
	      {
	        options.signature_input = options.input;
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

	   case 'u':
	      options.selected_users[options.num_selected_users]
		      = optarg;
	      options.num_selected_users++;
	      break;
	   
	   case 'n':
	      if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      if(options.personality != NULL)
	      {
		 errno = EINVAL;
                 perror("Personality can be given only once..");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */

	      }
	      options.personality = optarg;
	      command = 'n';
	      break;

	   case 'p':
	      if(options.personality != NULL)
	      {
		 errno = EINVAL;
                 perror("Personality can be given only once..");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
	      }
	      options.personality = optarg;

	      break;


           case 'x':
	      if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      command = 'x';
              break;
	   
	   case 'w':
	      if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      command = 'w';
              break;

	   case 'l':
	      if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      command = 'l';
              break;


	   case 'z':
	      if (command != '0'){
		 errno = EINVAL;
                 perror("Only one command allowed each time.");
                 exit(EXIT_FAILURE);
                 /* NOTREACHED */
              }
	      command = 'z';
              break;


	   case 'm':
	      options.merge = true;
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

	   case 'e':
	      options.use_aes_encryption = 1;
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
	select_personality(&options);
	if (sign_file(&options) != EXIT_SUCCESS) 
        {
          exit(EXIT_FAILURE);
          /* NOTREACHED */
        }
	break;
      
      case 'w':
	show_personality_list(&options);
	break;

      case 'l':
	show_user_list(&options);
	break;


      case 'c':
	select_personality(&options);
	if (check_file_signature(&options) != EXIT_SUCCESS) 
        {
          exit(EXIT_FAILURE);
          /* NOTREACHED */
        }
	break;

      case 'z':
	select_personality(&options);
	show_shared_zecret(&options);
	break;

      case 'n':
	add_personality(&options);
	break;

      case 'x':
	if (check_file_signature(&options) != EXIT_SUCCESS) 
        {
          exit(EXIT_FAILURE);
          /* NOTREACHED */
        }
	rewind(options.input);
	remove_signature_from_file(&options);
	break;

      case 'a':
	add_user(&options, argv[optind], argv[optind+1]);
	break;

      case '0':  /* on no command, print the public key */
	select_personality(&options);
        if(options.verbose >= 1) printf("Your public key:\n");
	enc = b64_encode(public_key, 32);
        fprintf(options.output, "%s %s\n",enc, name_of_entry);
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
    char aes_iv_B64[1024];
    char aes_public_key_B64[1024];
    char signature_public_key_B64[1024];
    unsigned char signed_filename[1024];
    unsigned char signature[64];
    unsigned char signature_public_key[64];
    unsigned char h[64];
    unsigned char checker[32];
    sha512_context hash;
    ge_p3 A;
    ge_p2 R;

    /* Search signature at the end of the file. */
    //fseek(options->input, 0L, SEEK_END);
    if(options->use_aes_encryption)
    {
      fseek(options->input, -(45+89+10+51+45+25+7), SEEK_END);
      int r = fscanf(options->input, "AES256\n%s\n%s\nSignature %s\n%s\n%s\n",
		   aes_iv_B64,aes_public_key_B64, signed_filename,
		   signature, signature_public_key_B64);
      if(r != 5)
      {
	printf("Signature format error.\n");
        return EXIT_FAILURE;
      }
    }
    else
    {
      fseek(options->input, -(45+89+10+51), SEEK_END);
      int r = fscanf(options->input, "Signature %s\n%s\n%s\n",
		   signed_filename,
		   signature, signature_public_key_B64);
      if(r != 3)
      {
	printf("Signature format error.\n");
        return EXIT_FAILURE;
      }
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

/* Cf. Tony Brown: bonybrown/tiny-AES128.C */
int pkcs7_padding_pad_buffer( uint8_t *buffer,  size_t data_length, size_t buffer_size, uint8_t modulus )
{
  uint8_t pad_byte = modulus - ( data_length % modulus ) ;
  if( data_length + pad_byte > buffer_size )
  {
    return -pad_byte;
  }
  int i = 0;
  while( i <  pad_byte)
  {
    buffer[data_length+i] = pad_byte;
    i++;
  }
  return pad_byte;
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
   
   size_t bytes_read = 0;
   int buffer_size = BUFFER_SIZE;
   struct AES_ctx ctx;
   unsigned char aes_iv_copy[AES_BLOCKLEN] = {};
   char* enc;
   char user_key[1024];

   if(options->use_aes_encryption)
   {
     if(options->verbose >= 1) printf("Using aes encryption\n");

     buffer_size = AES_BLOCKLEN;
     /* Create password based on zecret */
     calculate_shared_key(options, user_key);
     if(AES_BLOCKLEN != getrandom(aes_iv, AES_BLOCKLEN, 0))
     {
       printf("Could not get random values to initiate encryption\n");
       return EXIT_FAILURE;
     }
     memcpy(aes_iv_copy, aes_iv, AES_BLOCKLEN);
     AES_init_ctx_iv(&ctx, shared_secret, aes_iv);
     if(options->verbose >= 2) printf("Initialized aes encryption\n");
   }
   
   /* Copied from sign.c because hash called iterativley
    * in order to not load the complete file into ram. */
   if(options->verbose >= 2) printf("Signing file\n");

   sha512_context hash;
   unsigned char hram[64];
   unsigned char r[64];
   ge_p3 R;


   sha512_init(&hash);
   sha512_update(&hash, private_key + 32, 32);
   while( buffer_size == 
          (bytes_read=fread(buffer, 1, buffer_size, options->input)))
   {
     if(options->use_aes_encryption)
       AES_CBC_encrypt_buffer(&ctx, buffer, buffer_size);
     sha512_update(&hash, buffer, buffer_size);
     if(options->verbose >= 4) printf("sign full update\n");
   }
   if(options->use_aes_encryption)
   {
     if((16-bytes_read) != 
         pkcs7_padding_pad_buffer(buffer,bytes_read, 
		            buffer_size, 16 ))
     {
       printf("Could not get random values to initiate encryption\n");
       return EXIT_FAILURE;
     }
     AES_CBC_encrypt_buffer(&ctx, buffer, buffer_size);
     bytes_read = buffer_size;
   }
   sha512_update(&hash, buffer, bytes_read);
   if(options->verbose >= 4) printf("sign remainging: %li\n",bytes_read);
   sha512_final(&hash, r);

   sc_reduce(r);
   ge_scalarmult_base(&R, r);
   ge_p3_tobytes(signature, &R);

   sha512_init(&hash);
   sha512_update(&hash, signature, 32);
   sha512_update(&hash, public_key, 32);
   /*sha512_update(&hash, message, message_len);*/
   rewind(options->input);
   if(options->use_aes_encryption)
   {
     memcpy(aes_iv, aes_iv_copy, AES_BLOCKLEN); /* use same iv */
     AES_init_ctx_iv(&ctx, shared_secret, aes_iv);
   }
   while( buffer_size == 
          (bytes_read=fread(buffer, 1, buffer_size, options->input)))
   {
     if(options->use_aes_encryption)
       AES_CBC_encrypt_buffer(&ctx, buffer, buffer_size);
     sha512_update(&hash, buffer, buffer_size);
     if(options->verbose >= 4) printf("sha512 full update\n");
     if(options->merge)
     {
       fwrite(buffer, 1, bytes_read, options->output);
     }
   }
   if(options->use_aes_encryption)
   {
     if((16-bytes_read) != 
         pkcs7_padding_pad_buffer(buffer,bytes_read, 
		            buffer_size, 16 ))
     {
       printf("Could not get random values to initiate encryption\n");
       return EXIT_FAILURE;
     }
     AES_CBC_encrypt_buffer(&ctx, buffer, buffer_size);
     bytes_read = buffer_size;
   }
   sha512_update(&hash, buffer, bytes_read);
   if(options->merge)
   {
       fwrite(buffer, 1, bytes_read, options->output);
   }

   if(options->verbose >= 4) printf("sha512 remainging: %li\n",bytes_read);

   sha512_final(&hash, hram);

   sc_reduce(hram);
   sc_muladd(signature + 32, hram, private_key, r);
    
     /*fprintf(options->output, "\n");*/
   printf("\n");
   if(options->use_aes_encryption)
   {
     fprintf(options->output,"AES256\n");
     enc = b64_encode(aes_iv_copy, AES_BLOCKLEN);
     fprintf(options->output, "%s\n",enc);
     free( enc );
     fprintf(options->output, "%s\n",user_key);
   }

   fprintf(options->output, 
     "Signature %-50s\n",basename(options->input_filename));
   enc = b64_encode(signature, 64);
   fprintf(options->output,"%s\n",enc);
   free( enc ); 
   enc = b64_encode(public_key, 32);
   fprintf(options->output, "%s\n",enc);
   free( enc );
   

   if(options->verbose >= 2) printf("Done\n");
   return EXIT_SUCCESS;
}

int calculate_shared_key(options_t* options,
	char* public_key_user_b64)
{
   if (!options) 
   {
     errno = EINVAL;
     return EXIT_FAILURE;
   }

   if (options->num_selected_users <= 0) /*|| !options->output) {*/
   {
     printf("You need to selected at least one user with -u\n");
     errno = EINVAL;
     return EXIT_FAILURE;
   }

   if(0 != find_public_key_for_user(
			    options->selected_users[0], 
		            public_key_user_b64))
   {
     printf("Could not find user %s",options->selected_users[0]);
     errno = EINVAL;
     return EXIT_FAILURE;
   }

   unsigned char* public_user_key = 
	   b64_decode(public_key_user_b64, 44);

   ed25519_key_exchange(shared_secret,
                        public_user_key, 
			private_key);

   free( public_user_key );
   return EXIT_SUCCESS;
}

int show_shared_zecret(options_t *options)
{
   int result;
   char user_key[1024];
   if (EXIT_SUCCESS != 
       (result = calculate_shared_key(options, user_key)))
   {
     return result;
   }

   char* enc = b64_encode(shared_secret, 32);
   fprintf(options->output,"%s\n",enc);
   free( enc );

   return EXIT_SUCCESS;
}
