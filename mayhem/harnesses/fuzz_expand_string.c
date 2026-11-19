/* Util_ExpandString (lib/misc/util_misc.c): ~user and $VAR expansion of a path string. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "util.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
   /* Fixed, read-only environment so $VAR expansions have something to hit. */
   setenv("HOME", "/tmp", 1);
   setenv("USER", "mayhem", 1);
   setenv("FOO", "bar/baz", 1);
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size > 4096) return 0;
   char *s = malloc(size + 1);
   memcpy(s, data, size);
   s[size] = '\0';
   char *r = Util_ExpandString(s);
   free(r);
   free(s);
   return 0;
}
