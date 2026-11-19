#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer oracle for the code the fuzz targets cover. Upstream's own tests
# need a VM (they are built only with --enable-tests and talk to the hypervisor), so build.sh builds
# mayhem/oracle/ovt_oracle.c against the same libraries instead; this only RUNS it.
# Every expected check must print "PASS <name>": a check that fails, or never runs, is a failure.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

EXPECTED=(base64_decode base64_encode base64_reject
          datamap_roundtrip datamap_missing_key datamap_truncated_reject
          cpname_to cpname_from cpname_to_overflow
          escape_unescape escape_do escape_undo
          strutil_tokens strutil_reject timeutil_date
          jsmn_count jsmn_partial
          unicode_validate unicode_reject unicode_length
          saml_init saml_token_present saml_verify_valid saml_reject_tampered)

ORACLE="$SRC/ovt-oracle"
if [ ! -x "$ORACLE" ]; then
  echo "FAIL: $ORACLE missing — mayhem/build.sh should have built it" >&2
  emit_ctrf ovt-oracle 0 "${#EXPECTED[@]}"
  exit 1
fi

out="$("$ORACLE" 2>&1)"; rc=$?
printf '%s\n' "$out"
passed=0; failed=0
for t in "${EXPECTED[@]}"; do
  if grep -qx "PASS $t" <<<"$out"; then passed=$((passed + 1))
  else failed=$((failed + 1)); echo "not passed: $t" >&2; fi
done
# A non-zero exit with every check passed (e.g. a sanitizer report at exit) still fails the run.
[ "$rc" -eq 0 ] || { [ "$failed" -gt 0 ] || failed=1; echo "ovt-oracle exited $rc" >&2; }
emit_ctrf ovt-oracle "$passed" "$failed"
