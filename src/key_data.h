

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
extern char name_of_entry[1024];
extern char type_of_entry[12];


void init_data(options_t* opt);
void add_user(options_t* opt, const char* public_key, const char* username );

#ifdef __cplusplus
}
#endif /* key_data_H */

#endif

