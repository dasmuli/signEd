

#ifndef signEdMain_H
#define signEdMain_H 1

/* A struct to collect parameters. */
typedef struct {
  int           verbose;
  uint32_t      flags;
  FILE         *input;
  FILE         *output;
  char         *input_filename;
  char         *output_filename;
} options_t;

#ifdef __cplusplus
extern "C" {
#endif



#ifdef __cplusplus
}
#endif /* signEdMain_H */

#endif

