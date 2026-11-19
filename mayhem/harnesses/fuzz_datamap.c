/* DataMap wire format (lib/dataMap/dataMap.c): the typed key/value encoding used for RPC payloads. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "dataMap.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size > 0x7fffffff) return 0;
   char *buf = malloc(size ? size : 1);
   memcpy(buf, data, size);
   DataMap map;
   if (DataMap_Deserialize(buf, (int32)size, &map) == DMERR_SUCCESS) {
      char *s = NULL;
      if (DataMap_ToString(&map, NULL, 0, -1, -1, &s) == DMERR_SUCCESS) {
         free(s);
      }
      DataMap copy;
      if (DataMap_Copy(&map, &copy) == DMERR_SUCCESS) {
         char *ser = NULL;
         uint32 serLen = 0;
         if (DataMap_Serialize(&copy, &ser, &serLen) == DMERR_SUCCESS) {
            free(ser);
         }
         DataMap_Destroy(&copy);
      }
      DataMap_Destroy(&map);
   }
   free(buf);
   return 0;
}
