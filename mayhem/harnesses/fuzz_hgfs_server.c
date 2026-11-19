/*
 * HGFS server (lib/hgfsServer): the shared-folder file server inside the tools daemon. Each input is
 * one HGFS request packet (any protocol version V1-V4: open/read/write/search/rename/symlink/...),
 * delivered through the server manager's public entry, HgfsServerManager_ProcessPacket, exactly as
 * the tools daemon's hgfsServer plugin does (hgfsPlugin.c, HgfsServerRpcDispatch). The server is
 * registered and unregistered around every input, so no session or handle outlives an input.
 *
 * Environment shim: the share table normally comes from the host. The guest policy library hard-codes
 * a writable share of the WHOLE filesystem ("root" -> ""), which a fuzzer must not get, so this file
 * provides the HgfsServerPolicy_* lookup functions (hgfsServerPolicy.h) for one share, "root",
 * mapped to a scratch directory under $TMPDIR. The scratch directory is reset before every input
 * (a fixed file and subdirectory), so each input's result depends only on that input.
 */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <fcntl.h>
#include <ftw.h>
#include <unistd.h>
#include <sys/stat.h>
#include "vm_basic_types.h"
#include "hgfsServer.h"
#include "hgfsServerManager.h"
#include "hgfsServerPolicy.h"
#include "cpName.h"

static char gScratch[4096];
static HgfsSharedFolder gShare;

/* ---- share policy: one read/write share "root" -> scratch dir ---------------------------- */

static HgfsSharedFolder *
GetShare(char const *nameIn, size_t nameInLen)
{
   if (nameInLen == gShare.nameLen && strncasecmp(nameIn, gShare.name, nameInLen) == 0) {
      return &gShare;
   }
   return NULL;
}

HgfsNameStatus
HgfsServerPolicy_GetSharePath(char const *nameIn, size_t nameInLen, HgfsOpenMode mode,
                              size_t *sharePathLen, char const **sharePath)
{
   HgfsSharedFolder *s = GetShare(nameIn, nameInLen);
   if (!s) {
      return HGFS_NAME_STATUS_DOES_NOT_EXIST;
   }
   switch (HGFS_OPEN_MODE_ACCMODE(mode)) {
   case HGFS_OPEN_MODE_READ_ONLY:
   case HGFS_OPEN_MODE_WRITE_ONLY:
   case HGFS_OPEN_MODE_READ_WRITE:
      break;
   default:
      return HGFS_NAME_STATUS_FAILURE;
   }
   *sharePathLen = s->pathLen;
   *sharePath = s->path;
   return HGFS_NAME_STATUS_COMPLETE;
}

HgfsNameStatus
HgfsServerPolicy_ProcessCPName(char const *nameIn, size_t nameInLen, Bool *readAccess,
                               Bool *writeAccess, HgfsSharedFolderHandle *handle,
                               char const **shareBaseDir)
{
   HgfsSharedFolder *s = GetShare(nameIn, nameInLen);
   if (!s) {
      return HGFS_NAME_STATUS_DOES_NOT_EXIST;
   }
   *readAccess = s->readAccess;
   *writeAccess = s->writeAccess;
   *shareBaseDir = s->path;
   *handle = s->handle;
   return HGFS_NAME_STATUS_COMPLETE;
}

HgfsNameStatus
HgfsServerPolicy_GetShareOptions(char const *nameIn, size_t nameInLen,
                                 HgfsShareOptions *configOptions)
{
   char const *next;
   int len = CPName_GetComponent(nameIn, nameIn + nameInLen, &next);
   if (len < 0) {
      return HGFS_NAME_STATUS_FAILURE;
   }
   HgfsSharedFolder *s = GetShare(nameIn, len);
   if (!s) {
      return HGFS_NAME_STATUS_DOES_NOT_EXIST;
   }
   *configOptions = s->configOptions;
   return HGFS_NAME_STATUS_COMPLETE;
}

Bool
HgfsServerPolicy_IsShareOptionSet(HgfsShareOptions configOptions, uint32 option)
{
   return (configOptions & option) == option;
}

HgfsNameStatus
HgfsServerPolicy_GetShareMode(char const *nameIn, size_t nameInLen, HgfsOpenMode *mode)
{
   if (!GetShare(nameIn, nameInLen)) {
      return HGFS_NAME_STATUS_DOES_NOT_EXIST;
   }
   *mode = HGFS_OPEN_MODE_READ_WRITE;
   return HGFS_NAME_STATUS_COMPLETE;
}

static void *EnumInit(void) { static int st; st = 0; return &st; }
static Bool EnumGet(void *data, char const **name, size_t *len, Bool *done)
{
   int *st = data;
   if (*st == 0) {
      *name = gShare.name;
      *len = gShare.nameLen;
      *done = FALSE;
      *st = 1;
   } else {
      *done = TRUE;
   }
   return TRUE;
}
static Bool EnumExit(void *data) { return TRUE; }

Bool
HgfsServerPolicy_Init(HgfsInvalidateObjectsFunc invalidateObjects,
                      HgfsServerResEnumCallbacks *enumResources)
{
   enumResources->init = EnumInit;
   enumResources->get = EnumGet;
   enumResources->exit = EnumExit;
   return TRUE;
}

Bool
HgfsServerPolicy_Cleanup(void)
{
   return TRUE;
}

/* ---- scratch dir reset ------------------------------------------------------------------ */

static int Unlock(const char *p, const struct stat *sb, int type, struct FTW *f)
{
   if (type == FTW_D || type == FTW_DNR) chmod(p, 0700);
   return 0;
}
static int Remove(const char *p, const struct stat *sb, int type, struct FTW *f)
{
   if (f->level > 0) remove(p);
   return 0;
}
static void ResetScratch(void)
{
   chmod(gScratch, 0700);
   nftw(gScratch, Unlock, 16, FTW_PHYS);
   nftw(gScratch, Remove, 16, FTW_PHYS | FTW_DEPTH);
   char p[4200];
   snprintf(p, sizeof p, "%s/a.txt", gScratch);
   int fd = open(p, O_CREAT | O_WRONLY | O_TRUNC, 0600);
   if (fd >= 0) {
      (void)!write(fd, "hello hgfs\n", 11);
      close(fd);
   }
   snprintf(p, sizeof p, "%s/d", gScratch);
   mkdir(p, 0700);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   const char *tmp = getenv("TMPDIR");
   snprintf(gScratch, sizeof gScratch, "%s/ovthgfsXXXXXX", tmp && *tmp ? tmp : "/tmp");
   if (mkdtemp(gScratch) == NULL) {
      abort();
   }
   DblLnkLst_Init(&gShare.links);
   gShare.name = HGFS_SERVER_POLICY_ROOT_SHARE_NAME;
   gShare.nameLen = strlen(gShare.name);
   gShare.path = gScratch;
   gShare.pathLen = strlen(gScratch);
   gShare.readAccess = TRUE;
   gShare.writeAccess = TRUE;
   gShare.configOptions = 0;
   gShare.handle = HGFS_INVALID_FOLDER_HANDLE;
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   static char reply[HGFS_LARGE_PACKET_MAX];

   /*
    * hgfsPlugin.c passes the RPC arguments after the leading space; an empty packet with a
    * reply buffer is never sent (a zero-size reply buffer is the channel's ping).
    */
   if (size == 0 || size > HGFS_LARGE_PACKET_MAX) {
      return -1;
   }
   ResetScratch();

   HgfsServerMgrData mgr;
   HgfsServerManager_DataInit(&mgr, "fuzz", NULL, NULL);
   if (!HgfsServerManager_Register(&mgr)) {
      abort();
   }
   HgfsServer_SetHandleCounter(0);

   char *in = malloc(size);
   memcpy(in, data, size);
   size_t replySize = sizeof reply;
   HgfsServerManager_ProcessPacket(&mgr, in, size, reply, &replySize);
   free(in);

   HgfsServerManager_Unregister(&mgr);
   return 0;
}
