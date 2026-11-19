/* File_Rotate (lib/file/file.c): log rotation by rename or by renumbering, which parses the names
 * of the sibling files it finds next to the log. Each input lays out a fresh scratch directory:
 * byte 0 picks the rotation mode and count, the remaining lines become sibling file names. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include "vm_basic_types.h"
#include "file.h"

static void touch(const char *dir, const char *name) {
   char p[4096];
   snprintf(p, sizeof p, "%s/%s", dir, name);
   int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
   if (fd >= 0) close(fd);
}

static void wipe(const char *dir) {
   DIR *d = opendir(dir);
   if (d != NULL) {
      struct dirent *e;
      char p[4096];
      while ((e = readdir(d)) != NULL) {
         if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0) continue;
         snprintf(p, sizeof p, "%s/%s", dir, e->d_name);
         unlink(p);
      }
      closedir(d);
   }
   rmdir(dir);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
   if (size < 1 || size > 4096) return 0;
   uint8_t ctl = data[0];
   const char *tmp = getenv("TMPDIR");
   char dir[4096];
   snprintf(dir, sizeof dir, "%s/ovtrotXXXXXX", tmp && *tmp ? tmp : "/tmp");
   if (mkdtemp(dir) == NULL) return 0;

   /* Sibling names: one per line, at most 32; '/' and NUL are not valid in a file name. */
   char name[256];
   size_t n = 0, files = 0;
   for (size_t i = 1; i <= size && files < 32; i++) {
      if (i == size || data[i] == '\n') {
         name[n] = '\0';
         if (n > 0 && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            touch(dir, name);
            files++;
         }
         n = 0;
      } else if (data[i] != '/' && data[i] != '\0' && n < sizeof name - 1) {
         name[n++] = (char)data[i];
      }
   }
   touch(dir, "vmware.log");

   char path[4096];
   snprintf(path, sizeof path, "%s/vmware.log", dir);
   char *newName = NULL;
   File_Rotate(path, (ctl >> 1) % 8 + 1, (ctl & 1) ? TRUE : FALSE, &newName);
   free(newName);
   wipe(dir);
   return 0;
}
