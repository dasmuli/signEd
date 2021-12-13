

#ifndef signEdMain_H
#define signEdMain_H 1

#include <stdbool.h>

/* A struct to collect parameters. */
typedef struct {
  int           verbose;
  bool		merge;
  uint32_t      flags;
  FILE         *input;
  FILE         *output;
  FILE         *signature_input;
  char         *input_filename;
  char         *output_filename;
  char         *selected_users[256];
  int           num_selected_users;
  char         *personality;
  int           use_aes_encryption;
} options_t;

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif /* signEdMain_H */

#endif

