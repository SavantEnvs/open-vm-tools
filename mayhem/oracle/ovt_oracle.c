/* Known-answer checks for the open-vm-tools code the fuzz targets cover, linked against the same
 * libraries build.sh builds. Each check prints "PASS <name>" or "FAIL <name>: ..."; mayhem/test.sh
 * counts them against its list of expected names, so a check that never runs is a failure too. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "vm_basic_types.h"
#include "base64.h"
#include "dataMap.h"
#include "cpName.h"
#include "escape.h"
#include "jsmn.h"
#include "unicode.h"
#include "strutil.h"
#include "timeutil.h"
#include <glib.h>
#include "serviceInt.h"

static int failures = 0;

#define CHECK(name, cond, ...)                                    \
   do {                                                           \
      if (cond) { printf("PASS %s\n", name); }                    \
      else { printf("FAIL %s: ", name); printf(__VA_ARGS__);      \
             printf("\n"); failures++; }                          \
   } while (0)

static void t_base64(void)
{
   uint8 *out = NULL; size_t n = 0;
   Bool ok = Base64_EasyDecode("b3Blbi12bS10b29scw==", &out, &n);
   CHECK("base64_decode", ok && n == 13 && memcmp(out, "open-vm-tools", 13) == 0,
         "ok=%d n=%zu", ok, n);
   free(out);
   char *enc = NULL;
   ok = Base64_EasyEncode((const uint8 *)"VMware", 6, &enc);
   CHECK("base64_encode", ok && enc && strcmp(enc, "Vk13YXJl") == 0, "got %s", enc ? enc : "(null)");
   free(enc);
   ok = Base64_EasyDecode("@@@@", &out, &n);
   CHECK("base64_reject", !ok, "invalid base64 accepted");
   if (ok) free(out);
}

static void t_datamap(void)
{
   DataMap m, r;
   char *buf = NULL; uint32 len = 0;
   /* The map takes ownership of string and list payloads (dataMap.c: "the ownership of this list
    * will be passed to the map"), so they are heap copies. */
   char *s = strdup("hello");
   int64 *ints = malloc(3 * sizeof *ints);
   ints[0] = 1; ints[1] = -2; ints[2] = 1LL << 40;
   DataMap_Create(&m);
   DataMap_SetInt64(&m, 7, -123456789012LL, TRUE);
   DataMap_SetString(&m, 9, s, 5, TRUE);
   DataMap_SetInt64List(&m, 11, ints, 3, TRUE);
   ErrorCode e1 = DataMap_Serialize(&m, &buf, &len);
   ErrorCode e2 = DataMap_Deserialize(buf, (int32)len, &r);
   int64 v = 0; char *str = NULL; int32 slen = 0; int64 *lst = NULL; int32 llen = 0;
   ErrorCode e3 = DataMap_GetInt64(&r, 7, &v);
   ErrorCode e4 = DataMap_GetString(&r, 9, &str, &slen);
   ErrorCode e5 = DataMap_GetInt64List(&r, 11, &lst, &llen);
   CHECK("datamap_roundtrip",
         e1 == DMERR_SUCCESS && e2 == DMERR_SUCCESS && e3 == DMERR_SUCCESS &&
         e4 == DMERR_SUCCESS && e5 == DMERR_SUCCESS && v == -123456789012LL &&
         slen == 5 && memcmp(str, "hello", 5) == 0 && llen == 3 &&
         lst[0] == 1 && lst[1] == -2 && lst[2] == (1LL << 40),
         "e=%d/%d/%d/%d/%d v=%lld slen=%d llen=%d", e1, e2, e3, e4, e5, (long long)v, slen, llen);
   CHECK("datamap_missing_key", DataMap_GetType(&r, 8) == DMFIELDTYPE_EMPTY, "key 8 present");
   ErrorCode e6 = DataMap_Deserialize(buf, (int32)len - 1, &r);
   CHECK("datamap_truncated_reject", e6 != DMERR_SUCCESS, "truncated buffer accepted");
   DataMap_Destroy(&m);
   if (e2 == DMERR_SUCCESS) DataMap_Destroy(&r);
   free(buf);
}

static void t_cpname(void)
{
   char out[64];
   memset(out, 'X', sizeof out);
   int n = CPName_ConvertTo("a/b/c", sizeof out, out);
   CHECK("cpname_to", n == 5 && memcmp(out, "a\0b\0c", 5) == 0, "n=%d", n);
   const char *in = "a\0b\0c";
   size_t inSize = 5, outSize = sizeof out;
   char *o = out;
   memset(out, 0, sizeof out);
   int r = CPName_ConvertFrom(&in, &inSize, &outSize, &o);
   CHECK("cpname_from", r >= 0 && strcmp(out, "/a/b/c") == 0, "r=%d out=%s", r, out);
   n = CPName_ConvertTo("a/b/c", 3, out);
   CHECK("cpname_to_overflow", n < 0, "n=%d with a 3-byte buffer", n);
}

static void t_escape(void)
{
   char *u = Escape_Unescape('\\', "a\\\\b\\c\\");
   CHECK("escape_unescape", u && strcmp(u, "a\\bc") == 0, "got %s", u ? u : "(null)");
   free(u);
   int bytesToEsc[256] = { 0 };
   bytesToEsc['/'] = 1; bytesToEsc['%'] = 1;
   size_t n = 0;
   char *e = Escape_Do('%', bytesToEsc, "a/b%c", 5, &n);
   CHECK("escape_do", e && n == 9 && memcmp(e, "a%2Fb%25c", 9) == 0, "got %.*s", (int)n, e ? e : "");
   size_t m = 0;
   char *d = e ? Escape_Undo('%', e, n, &m) : NULL;
   CHECK("escape_undo", d && m == 5 && memcmp(d, "a/b%c", 5) == 0, "got %.*s", (int)m, d ? d : "");
   free(e); free(d);
}

static void t_strutil(void)
{
   const char *args = "  copy\t-5,4294967295 9223372036854775807";
   unsigned int idx = 0;
   char *t1 = StrUtil_GetNextToken(&idx, args, " \t,");
   int32 i = 0; uint32 u = 0; int64 l = 0;
   Bool okI = StrUtil_GetNextIntToken(&i, &idx, args, " \t,");
   Bool okU = StrUtil_GetNextUintToken(&u, &idx, args, " \t,");
   Bool okL = StrUtil_GetNextInt64Token(&l, &idx, args, " \t,");
   char *t5 = StrUtil_GetNextToken(&idx, args, " \t,");
   CHECK("strutil_tokens", t1 && strcmp(t1, "copy") == 0 && okI && i == -5 && okU &&
         u == 4294967295u && okL && l == 9223372036854775807LL && t5 == NULL,
         "t1=%s i=%d u=%u l=%lld", t1 ? t1 : "(null)", (int)i, (unsigned)u, (long long)l);
   free(t1); free(t5);
   int32 big = 0;
   CHECK("strutil_reject", !StrUtil_StrToInt(&big, "4294967296") && !StrUtil_StrToInt(&big, "12x") &&
         StrUtil_StrToInt(&big, "0x10") && big == 16,
         "out-of-range/trailing junk accepted");
   TimeUtil_Date d = { 0 };
   Bool okD = TimeUtil_StringToDate(&d, "2026-11-19");
   CHECK("timeutil_date", okD && d.year == 2026 && d.month == 11 && d.day == 19 &&
         !TimeUtil_StringToDate(&d, "2026x11x19"),
         "ok=%d %u-%u-%u", okD, d.year, d.month, d.day);
}

static void t_jsmn(void)
{
   const char *js = "{\"a\": [1, 2, {\"b\": null}], \"c\": \"x\"}";
   jsmn_parser p; jsmntok_t t[32];
   jsmn_init(&p);
   int n = jsmn_parse(&p, js, strlen(js), t, 32);
   /* object, "a", array, 1, 2, object, "b", null, "c", "x" */
   CHECK("jsmn_count", n == 10 && t[0].type == JSMN_OBJECT && t[0].size == 2 &&
         t[2].type == JSMN_ARRAY && t[2].size == 3 && t[9].type == JSMN_STRING &&
         t[9].end - t[9].start == 1 && js[t[9].start] == 'x', "n=%d", n);
   jsmn_init(&p);
   n = jsmn_parse(&p, "{\"a\": [1, 2", 11, t, 32);
   CHECK("jsmn_partial", n == JSMN_ERROR_PART, "n=%d", n);
}

static void t_unicode(void)
{
   /* U+00E9 U+4E2D in UTF-8 */
   const char *s = "\xC3\xA9\xE4\xB8\xAD";
   CHECK("unicode_validate", Unicode_IsBufferValid(s, 5, STRING_ENCODING_UTF8), "valid UTF-8 rejected");
   CHECK("unicode_reject", !Unicode_IsBufferValid("\xC3\x28", 2, STRING_ENCODING_UTF8),
         "invalid UTF-8 accepted");
   CHECK("unicode_length", Unicode_LengthInCodePoints(s) == 2, "len=%d",
         (int)Unicode_LengthInCodePoints(s));
}

/* VGAuth SAML: the signed token from upstream's vgauth/test/main.c (valid until 2116) must verify
 * and name its subject; the same token with one signed byte changed must be rejected. */
PrefHandle gPrefs = NULL;
char *gInstallDir = NULL;

VGAuthError
ServiceVerifyAndCheckTrustCertChainForSubject(int numCerts, const char **pemCertChain,
                                              const char *userName, ServiceSubject *subj,
                                              char **userNameOut, ServiceAliasInfo **verifyAi)
{
   (void)numCerts; (void)pemCertChain; (void)userName; (void)subj; (void)userNameOut;
   (void)verifyAi;
   abort();   /* the alias store is not linked; SAML_VerifyBearerToken never calls this */
}

static void QuietLog(const gchar *d, GLogLevelFlags l, const gchar *m, gpointer u)
{
   (void)d; (void)l; (void)m; (void)u;
}

static char *ReadFile(const char *path)
{
   gchar *buf = NULL;
   return g_file_get_contents(path, &buf, NULL, NULL) ? buf : NULL;
}

static void t_saml(void)
{
   g_log_set_default_handler(QuietLog, NULL);
   gInstallDir = g_strdup("/nonexistent");
   gPrefs = Pref_Init("/nonexistent/vgauth.conf");
   g_key_file_set_string(gPrefs->keyFile, VGAUTH_PREF_GROUP_NAME_SERVICE,
                         VGAUTH_PREF_SAML_SCHEMA_DIR, OVT_SAML_SCHEMA_DIR);
   VGAuthError ie = SAML_Init();
   CHECK("saml_init", ie == VGAUTH_E_OK, "SAML_Init=%d", (int)ie);
   char *tok = ReadFile(OVT_SAML_TOKEN);
   CHECK("saml_token_present", tok != NULL, "cannot read %s", OVT_SAML_TOKEN);
   if (ie != VGAUTH_E_OK || tok == NULL) {
      printf("FAIL saml_verify_valid: skipped\nFAIL saml_reject_tampered: skipped\n");
      failures += 2;
      return;
   }
   char *user = NULL, *subj = NULL;
   ServiceAliasInfo *ai = NULL;
   VGAuthError e = SAML_VerifyBearerToken(tok, NULL, &user, &subj, &ai);
   CHECK("saml_verify_valid", e == VGAUTH_E_OK && subj && strcmp(subj, "SmokeSubject") == 0,
         "err=%d subject=%s", (int)e, subj ? subj : "(null)");
   g_free(subj); subj = NULL;
   /* Change the signed subject name: the digest no longer matches. */
   char *p = strstr(tok, "SmokeSubject");
   VGAuthError e2 = VGAUTH_E_OK;
   if (p) {
      p[0] = 'X';
      e2 = SAML_VerifyBearerToken(tok, NULL, &user, &subj, &ai);
   }
   CHECK("saml_reject_tampered", p && e2 != VGAUTH_E_OK, "tampered token accepted (err=%d)", (int)e2);
   g_free(subj);
   g_free(tok);
}

int main(void)
{
   setvbuf(stdout, NULL, _IONBF, 0);   /* keep the PASS/FAIL lines printed before any abort */
   t_base64();
   t_datamap();
   t_cpname();
   t_escape();
   t_strutil();
   t_jsmn();
   t_unicode();
   t_saml();
   printf("oracle: %d failure(s)\n", failures);
   return failures ? 1 : 0;
}
