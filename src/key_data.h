

#ifndef key_data_H
#define key_data_H 1

#include "signEdMain.h"

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned char seed[32];
extern unsigned char public_key[32];
extern unsigned char private_key[64];
extern unsigned char signature[64];
extern unsigned char shared_secret[32];
extern char name_of_entry[1024];
extern char type_of_entry[12];


void init_data(options_t* opt);
int add_user(options_t* opt, const char* public_key, const char* username );
int search_for_public_key(char* signature_public_key, char* public_key_user);
int remove_signature_from_file(options_t* options);
int find_public_key_for_user(char* username, 
		             char* public_key_b64);
int add_personality(options_t *options);
int select_personality(options_t *options);
int show_personality_list(options_t *options);
int show_user_list(options_t *options);
int search_key_entry(FILE* file_handle,
     char* filter_command, char* filter_user,
     char* filter_public_key, char* filter_private_key,
     char* out_command, char* out_user, 
     char* out_public_key, char* out_private_key);

#ifdef __cplusplus
}
#endif /* key_data_H */

#endif

