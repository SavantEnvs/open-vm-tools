/* Dictionary line codec (lib/dict/dictll.c): `name = "value"` config lines with escapes. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "dynbuf.h"
#include "dictll.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   char *buf = malloc(size ? size : 1);
   memcpy(buf, data, size);
   const char *p = buf;
   size_t left = size;
   DynBuf db;
   DynBuf_Init(&db);
   while (left > 0) {
      char *line = NULL, *name = NULL, *value = NULL;
      const char *next = DictLL_UnmarshalLine(p, left, &line, &name, &value);
      if (next == NULL) break;
      if (name != NULL && value != NULL) {
         DictLL_MarshalLine(&db, name, value);
      }
      free(line);
      free(name);
      free(value);
      left -= (size_t)(next - p);
      p = next;
   }
   DynBuf_Destroy(&db);
   free(buf);
   return 0;
}
