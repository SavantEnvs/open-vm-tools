/* Unicode / codeset conversion (lib/unicode, lib/misc/codeset*.c): the first byte picks the source
 * encoding; valid buffers are converted to UTF-8 and back out to another encoding. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "unicode.h"
#include "codeset.h"

static const StringEncoding encs[] = {
   STRING_ENCODING_UTF8, STRING_ENCODING_UTF16_LE, STRING_ENCODING_UTF16_BE,
   STRING_ENCODING_UTF32_LE, STRING_ENCODING_US_ASCII, STRING_ENCODING_ISO_8859_1,
};
#define NENC (sizeof encs / sizeof encs[0])

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size < 1 || size > 65536) return 0;
   uint8_t sel = data[0];
   data++; size--;
   char *buf = malloc(size + 1);
   memcpy(buf, data, size);
   buf[size] = '\0';
   StringEncoding from = encs[sel % NENC];
   StringEncoding to = encs[(sel / NENC) % NENC];

   /* Contract: Unicode_AllocWithLength requires a valid buffer (it panics otherwise). */
   if (Unicode_IsBufferValid(buf, size, from)) {
      char *u = Unicode_AllocWithLength(buf, size, from);
      if (u != NULL) {
         void *b = Unicode_GetAllocBytes(u, to);
         free(b);
         free(u);
      }
   }
   char *o = NULL; size_t ol = 0;
   if (CodeSet_Utf16leToUtf8(buf, size, &o, &ol)) free(o);
   o = NULL;
   if (CodeSet_Utf8ToUtf16le(buf, size, &o, &ol)) free(o);
   /* CodeSet_Utf8FormDToUtf8FormC is NOT_IMPLEMENTED() outside macOS (codesetOld.c), so not called. */
   CodeSet_Validate(buf, size, "UTF-8");
   free(buf);
   return 0;
}
