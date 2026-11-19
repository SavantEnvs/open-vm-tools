/* HGFS cross-platform name codec (lib/hgfs): CPName_* and HgfsEscape_*, which convert the
 * names in every HGFS request between wire form and local paths. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "cpName.h"
#include "cpNameLite.h"
#include "hgfsEscape.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size > 4096) return 0;
   char *in = malloc(size + 1);
   memcpy(in, data, size);
   in[size] = '\0';
   char out[8192];

   /* Wire (NUL-separated) -> local. */
   {
      const char *p = in;
      size_t inSize = size, outSize = sizeof out;
      char *o = out;
      CPName_ConvertFrom(&p, &inSize, &outSize, &o);
   }
   {
      const char *p = in;
      size_t inSize = size, outSize = sizeof out;
      char *o = out;
      CPName_ConvertFromRoot(&p, &inSize, &outSize, &o);
   }
   {
      const char *next = NULL, *cur = in, *end = in + size;
      int n = 0;
      while (cur < end && n++ < 1024) {
         int len = CPName_GetComponent(cur, end, &next);
         if (len < 0 || next == cur) break;
         cur = next;
      }
   }
   /* Local -> wire. */
   CPName_ConvertTo(in, sizeof out, out);
   CPName_LinuxConvertTo(in, sizeof out, out);
   CPName_WindowsConvertTo(in, sizeof out, out);

   /* Escape round trip. */
   uint32 sz = (uint32)size;
   /* HgfsEscape_GetSize/Do require sizeIn > 0 (ASSERT in hgfsEscape.c). */
   int esc = size > 0 ? HgfsEscape_GetSize(in, sz) : -1;
   if (esc >= 0) {
      uint32 outLen = sz + (uint32)esc + 1;
      char *e = malloc(outLen);
      int r = HgfsEscape_Do(in, sz, outLen, e);
      if (r >= 0) {
         HgfsEscape_Undo(e, (uint32)r);
      }
      free(e);
   }
   char *u = malloc(size + 1);
   memcpy(u, in, size + 1);
   HgfsEscape_Undo(u, sz);
   free(u);
   free(in);
   return 0;
}
