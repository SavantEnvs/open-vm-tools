/* VIX guest-ops request/response messages (lib/foundryMsg/foundryMsg.c): the host sends these
 * to the tools daemon. Validate first, exactly as the daemon does, then parse. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "vixOpenSource.h"
#include "vixCommands.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size < 1) return 0;
   int mode = data[0] & 1;
   data++; size--;
   /* Heap copy so ASan sees reads past the end of the message. */
   char *buf = malloc(size ? size : 1);
   memcpy(buf, data, size);
   if (mode == 0) {
      if (VixMsg_ValidateRequestMsg(buf, size) == VIX_OK) {
         VixCommandRequestHeader *h = (VixCommandRequestHeader *)buf;
         if (h->commonHeader.totalMessageLength <= size) {
            int options = 0;
            VixPropertyListImpl pl;
            VixPropertyList_Initialize(&pl);
            VixMsg_ParseGenericRequestMsg((VixCommandGenericRequest *)buf, &options, &pl);
            VixPropertyList_RemoveAllWithoutHandles(&pl);
            char *name = NULL, *value = NULL;
            /* On success name/value point into buf (foundryMsg.c:999); nothing to free. */
            if (VixMsg_ParseWriteVariableRequest((VixMsgWriteVariableRequest *)buf,
                                                 &name, &value) == VIX_OK) {
               volatile size_t n = strlen(name) + strlen(value);
               (void)n;
            }
         }
      }
   } else {
      if (VixMsg_ValidateResponseMsg(buf, size) == VIX_OK) {
         VixCommandResponseHeader *h = (VixCommandResponseHeader *)buf;
         if (h->commonHeader.totalMessageLength <= size) {
            const char *s = NULL;
            VixMsg_ParseSimpleResponseWithString(h, &s);
         }
      }
   }
   free(buf);
   return 0;
}
