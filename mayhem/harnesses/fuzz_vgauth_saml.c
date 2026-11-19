/* VGAuth SAML bearer-token verification (vgauth/serviceImpl/saml-xmlsec1.c): the input is the token
 * text a VGAuth client hands the (root) VGAuth service in a ValidateSamlBearerToken request. It is
 * parsed by libxml2 (entities, DTD load), schema-validated, its Subject/Conditions checked, and its
 * XML-DSig signature verified with xmlsec1 against the certificates it carries.
 *
 * Entry point: SAML_VerifyBearerToken(), which is VerifySAMLToken() with hostVerified=FALSE (full
 * signature check) and no alias-store lookup. The alias store (verify.c/alias.c, reached only from
 * SAML_VerifyBearerTokenAndChain) needs the service's on-disk store and user database, so it is not
 * linked; ServiceVerifyAndCheckTrustCertChainForSubject below only satisfies the linker and is never
 * called on this path.
 *
 * Process-global state kept across inputs, read-only after init: the parsed SAML schemas and their
 * validation context, the prefs keyfile (schema dir only) and the xmlsec1/OpenSSL init. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include "serviceInt.h"

#ifndef OVT_SAML_SCHEMA_DIR
#error "build.sh defines OVT_SAML_SCHEMA_DIR"
#endif

PrefHandle gPrefs = NULL;
char *gInstallDir = NULL;

VGAuthError
ServiceVerifyAndCheckTrustCertChainForSubject(int numCerts, const char **pemCertChain,
                                              const char *userName, ServiceSubject *subj,
                                              char **userNameOut, ServiceAliasInfo **verifyAi)
{
   (void)numCerts; (void)pemCertChain; (void)userName; (void)subj; (void)userNameOut;
   (void)verifyAi;
   abort();   /* not reachable from SAML_VerifyBearerToken */
}

static void QuietLog(const gchar *d, GLogLevelFlags l, const gchar *m, gpointer u)
{
   (void)d; (void)l; (void)m; (void)u;
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
   (void)argc; (void)argv;
   /* The service logs every rejected token through g_warning/g_debug; drop it (not an assert:
    * no G_LOG_FLAG_FATAL is set anywhere in this path). */
   g_log_set_default_handler(QuietLog, NULL);
   gInstallDir = g_strdup("/nonexistent");
   gPrefs = Pref_Init("/nonexistent/vgauth.conf");
   g_key_file_set_string(gPrefs->keyFile, VGAUTH_PREF_GROUP_NAME_SERVICE,
                         VGAUTH_PREF_SAML_SCHEMA_DIR, OVT_SAML_SCHEMA_DIR);
   if (SAML_Init() != VGAUTH_E_OK) {
      abort();   /* schemas or xmlsec1 failed to load: a build problem, not an input */
   }
   return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
   /* The service receives the token as a NUL-terminated string (GMarkup text of the request). */
   char *tok = malloc(size + 1);
   memcpy(tok, data, size);
   tok[size] = '\0';
   char *userOut = NULL, *subjOut = NULL;
   ServiceAliasInfo *ai = NULL;
   SAML_VerifyBearerToken(tok, NULL, &userOut, &subjOut, &ai);
   g_free(subjOut);
   g_free(userOut);
   free(tok);
   return 0;
}
