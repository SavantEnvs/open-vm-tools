/* VIX encoded / obfuscated strings (lib/foundryMsg/foundryMsg.c VixMsgDecodeBuffer): the
 * credentials and results the host sends to the guestops plugin (vixTools.c, foundryToolsDaemon.c).
 * Byte 0 picks the decoder; the rest, NUL-terminated, is the encoded string.
 * Built but NOT a Mayhem target: VixMsgDecodeBuffer has several shallow bugs (signed-char table
 * index, VIX_OK with a NULL result on bad base64, unterminated decode results) that fire on most
 * inputs, so libFuzzer restarts die before Mayhem's 5-iteration probe. Reproducers:
 * mayhem/vix-decode/known-findings/. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "vixOpenSource.h"
#include "vixCommands.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size < 1) return 0;
   uint8_t sel = data[0] & 1;
   data++; size--;
   char *buf = malloc(size + 1);
   memcpy(buf, data, size);
   buf[size] = '\0';
   if (sel) {
      char *dec = NULL;
      if (VixMsg_DecodeString(buf, &dec) == VIX_OK) {
         free(dec);
      }
   } else {
      char *user = NULL, *pass = NULL;
      if (VixMsg_DeObfuscateNamePassword(buf, &user, &pass) == VIX_OK) {
         free(user);
         free(pass);
      }
   }
   free(buf);
   return 0;
}
