/*
 * Linked into every fuzz and -standalone binary. libvmtools' Panic() (and so every VERIFY/ASSERT
 * failure) logs at G_LOG_LEVEL_ERROR; with no handler installed glib then traps with SIGTRAP
 * (G_BREAKPOINT), which libFuzzer does not treat as a crash: the process just dies, no crash
 * report is written, and Mayhem marks the whole run failed. This handler turns that into an
 * abort(), so a failed VERIFY becomes an ordinary, triageable crash. Other levels go to glib's
 * default handler unchanged. Nothing is hidden: the assert still fires, it only aborts cleanly.
 */
#include <stdio.h>
#include <stdlib.h>
#include <glib.h>

static void
OvtFuzzLogHandler(const gchar *domain, GLogLevelFlags level, const gchar *msg, gpointer data)
{
   if (level & (G_LOG_LEVEL_ERROR | G_LOG_FLAG_FATAL)) {
      fprintf(stderr, "%s: fatal: %s\n", domain ? domain : "vmtools", msg ? msg : "");
      fflush(stderr);
      abort();
   }
   g_log_default_handler(domain, level, msg, data);
}

__attribute__((constructor)) static void
OvtFuzzInstallPanicAbort(void)
{
   g_log_set_default_handler(OvtFuzzLogHandler, NULL);
}
