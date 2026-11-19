/* jsmn JSON tokenizer (lib/jsmn), used on container-runtime replies. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "jsmn.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   char *buf = malloc(size ? size : 1);
   memcpy(buf, data, size);
   jsmn_parser p;
   jsmntok_t toks[256];
   jsmn_init(&p);
   jsmn_parse(&p, buf, size, toks, 256);
   jsmn_init(&p);
   jsmn_parse(&p, buf, size, NULL, 0);
   free(buf);
   return 0;
}
