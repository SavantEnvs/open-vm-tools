/* String decoders used on host-supplied RPC/guestops strings: Base64 (lib/misc/base64.c), the
 * escape codecs (lib/misc/escape.c), the RPC argument tokenizers and number parsers
 * (lib/misc/strutil.c: what the tools daemon's RPC handlers use to split "cmd arg1 arg2" from the
 * host) and the date parser (lib/misc/timeutil.c). The first byte picks the decoder. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "base64.h"
#include "escape.h"
#include "strutil.h"
#include "timeutil.h"

/* The delimiters the RPC handlers split host arguments on (e.g. " " and " \t"). */
static const char kDelims[] = " \t,";

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size < 1) return 0;
   uint8_t sel = data[0];
   data++; size--;
   char *s = malloc(size + 1);
   memcpy(s, data, size);
   s[size] = '\0';
   switch (sel % 12) {
   case 0: {
      uint8 *t = NULL; size_t tl = 0;
      if (Base64_EasyDecode(s, &t, &tl)) free(t);
      break;
   }
   case 1: {
      size_t cap = Base64_DecodedLength(s, size);
      uint8 *t = malloc(cap + 1); size_t tl = 0;
      Base64_ChunkDecode(s, size, t, cap, &tl);
      Base64_ValidEncoding(s, size);
      free(t);
      break;
   }
   case 2: {
      size_t o = 0;
      void *r = Escape_Undo('%', s, size, &o);
      free(r);
      break;
   }
   case 3: {
      size_t o = 0;
      void *r = Escape_AnsiToUnix(s, size, &o);
      free(r);
      break;
   }
   case 4:
      Escape_UnescapeCString(s);
      break;
   case 5: {
      char *r = Escape_Unescape('\\', s);
      free(r);
      break;
   }
   case 6: {
      char out[64];
      Escape_UndoFixed('#', s, size, out, sizeof out);
      break;
   }
   case 7: {
      /* Tokenize the whole argument string, as the RPC handlers do. */
      unsigned int idx = 0;
      char *tok;
      while ((tok = StrUtil_GetNextToken(&idx, s, kDelims)) != NULL) {
         free(tok);
      }
      break;
   }
   case 8:
   case 9:
   case 10: {
      /* A run of numeric arguments: each call consumes one token (valid or not). */
      size_t len = strlen(s);
      unsigned int idx = 0;
      while (idx < len) {
         unsigned int before = idx;
         if (sel % 12 == 8) {
            int32 v; StrUtil_GetNextIntToken(&v, &idx, s, kDelims);
         } else if (sel % 12 == 9) {
            uint32 v; StrUtil_GetNextUintToken(&v, &idx, s, kDelims);
         } else {
            int64 v; StrUtil_GetNextInt64Token(&v, &idx, s, kDelims);
         }
         if (idx == before) break;
      }
      break;
   }
   case 11: {
      int32 i32; uint32 u32; int64 i64; uint64 u64; size_t sz; double d;
      TimeUtil_Date date = { 0 };
      StrUtil_StrToInt(&i32, s);
      StrUtil_StrToUint(&u32, s);
      StrUtil_StrToInt64(&i64, s);
      StrUtil_StrToUint64(&u64, s);
      StrUtil_StrToSizet(&sz, s);
      StrUtil_StrToDouble(&d, s);
      TimeUtil_StringToDate(&date, s);
      break;
   }
   }
   free(s);
   return 0;
}
