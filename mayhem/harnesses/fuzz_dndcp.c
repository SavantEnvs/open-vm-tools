/* Drag-and-drop / copy-paste messages from the host (services/plugins/dndcp/dnd): the v4 message
 * codec (dndCPMsgV4.c, single and multi-packet), the v3 message codec (dndMsg.c) and the clipboard
 * wire format (dndClipboard.c). Byte 0 picks the decoder. The v4 multi-packet mode splits the rest
 * into packets, each prefixed by a little-endian uint16 length, fed to one message in order. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "dndClipboard.h"
#include "dndMsg.h"
#include "dndCPMsgV4.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size < 1) return 0;
   uint8_t sel = data[0] % 4;
   data++; size--;
   uint8_t *buf = malloc(size ? size : 1);
   memcpy(buf, data, size);

   switch (sel) {
   case 0: {
      CPClipboard clip;
      CPClipboard_Init(&clip);
      if (CPClipboard_Unserialize(&clip, buf, size)) {
         DynBuf db;
         DynBuf_Init(&db);
         CPClipboard_Serialize(&clip, &db);
         DynBuf_Destroy(&db);
      }
      CPClipboard_Destroy(&clip);
      break;
   }
   case 1: {
      DnDMsg msg;
      DnDMsg_Init(&msg);
      if (DnDMsg_UnserializeHeader(&msg, buf, size) == DNDMSG_SUCCESS) {
         /* dndRpcV3: the arguments follow the fixed header in the same buffer. */
         size_t hdr = DNDMSG_HEADERSIZE_V3;
         if (size >= hdr) {
            DnDMsg_UnserializeArgs(&msg, buf + hdr, size - hdr);
         }
      }
      DnDMsg_Destroy(&msg);
      break;
   }
   case 2: {
      DnDCPMsgV4 msg;
      DnDCPMsgV4_Init(&msg);
      DnDCPMsgV4_UnserializeSingle(&msg, buf, size);
      DnDCPMsgV4_Destroy(&msg);
      break;
   }
   case 3: {
      DnDCPMsgV4 msg;
      DnDCPMsgV4_Init(&msg);
      size_t off = 0;
      while (off + 2 <= size) {
         size_t len = buf[off] | (buf[off + 1] << 8);
         off += 2;
         if (len > size - off) len = size - off;
         /* Each packet in its own allocation, as each arrives in its own RPC. */
         uint8_t *pkt = malloc(len ? len : 1);
         memcpy(pkt, buf + off, len);
         Bool ok = DnDCPMsgV4_UnserializeMultiple(&msg, pkt, len);
         free(pkt);
         off += len;
         if (!ok) break;
      }
      DnDCPMsgV4_Destroy(&msg);
      break;
   }
   }
   free(buf);
   return 0;
}
