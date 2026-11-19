# VixMsgDecodeBuffer findings (fuzz_vix_decode)

Run with `/mayhem/fuzz_vix_decode-standalone <file>`. All three are in upstream
`open-vm-tools/lib/foundryMsg/foundryMsg.c` and are reachable with host-supplied guestops strings.

- `decode-escape-signed-index`: a `\` followed by a byte >= 0x80 indexes
  `ObfuscatedToPlainCharMap[(unsigned int)(*srcPtr)]` with a sign-extended `char` (line 1455):
  global out-of-bounds read.
- `deobfuscate-strlen-null`: invalid base64 makes `VixMsgDecodeBuffer` return `VIX_OK` with a NULL
  result, which `VixMsg_DeObfuscateNamePassword` passes to `strlen` (line 1189).
- `deobfuscate-unterminated`: the decoded name/password buffer is not NUL-terminated, so `strlen`
  in `VixMsg_DeObfuscateNamePassword` reads past the heap allocation.
