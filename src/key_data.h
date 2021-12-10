

#ifndef key_data_h
#define key_data_H 1

#ifdef __cplusplus
extern "C" {
#endif

extern unsigned char seed[32];
extern unsigned char public_key[32];
extern unsigned char private_key[64];
extern unsigned char signature[64];

void init_data();

#ifdef __cplusplus
}
#endif /* key_data_H */

#endif

