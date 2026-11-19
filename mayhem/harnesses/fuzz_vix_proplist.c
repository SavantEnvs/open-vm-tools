/* VIX property lists (lib/foundryMsg/foundryPropertyListCommon.c): the serialized property list
 * carried in guestops requests from the host. Deserialize, then re-serialize what was accepted.
 * The encoded/obfuscated credential-string decoders live in fuzz_vix_decode.c (no Mayhem target:
 * they crash on most inputs, see mayhem/vix-decode/known-findings/). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "vixOpenSource.h"
#include "vixCommands.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   /* Heap copy so ASan sees reads past the end of the buffer. */
   char *buf = malloc(size ? size : 1);
   memcpy(buf, data, size);

   VixPropertyListImpl pl;
   VixPropertyList_Initialize(&pl);
   if (VixPropertyList_Deserialize(&pl, buf, size, VIX_PROPERTY_LIST_BAD_ENCODING_ERROR) == VIX_OK) {
      size_t outSize = 0;
      char *out = NULL;
      if (VixPropertyList_Serialize(&pl, FALSE, &outSize, &out) == VIX_OK) {
         free(out);
      }
   }
   VixPropertyList_RemoveAllWithoutHandles(&pl);
   free(buf);
   return 0;
}
