#!/usr/bin/env bash
#
# mayhem/build.sh — build open-vm-tools' convenience libraries with the sanitizers + SanCov, then the
# libFuzzer harnesses in mayhem/harnesses/ (+ a -standalone reproducer each) linked against them.
# Runs as `mayhem` in /mayhem; re-runnable and offline (all deps come from apt in the Dockerfile).
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

OVT="$SRC/open-vm-tools"
OUT="$SRC"
cd "$OVT"

# 1) The project: autotools, in tree (every generated file is covered by upstream's .gitignore).
#    Only the libraries are needed; the daemons/CLIs do not link with --disable-shared and are not
#    fuzz targets. -fsanitize=fuzzer-no-link puts SanCov on the project code. Project CFLAGS add
#    -Werror; -Wno-error keeps newer-clang warnings from failing the build.
# UBSan stays fully on for the project, except for a few named checks in the few files whose benign
# idiom fires on nearly every input (ASan and the rest of UBSan stay halting there too). Each relaxed
# directory/object is built first with a CFLAGS override, so the recursive `make -C lib` that
# follows finds it up to date and builds everything else strict:
#   lib/dataMap            alignment         HashMap stores the 8-byte entry pointer right after a
#                                            4-byte key, so dataMap.c:1656/691 read it misaligned
#   lib/foundryMsg         alignment         VixPropertyList_Deserialize reads each 4-byte length
#    foundryPropertyListCommon.lo            through an (int *) at any byte offset of the serialized
#                                            buffer (foundryPropertyListCommon.c:549)
#   lib/misc codesetOld.lo pointer-overflow  NULL+0 on a new, empty DynBuf (codesetOld.c:218)
#   lib/hgfsServer*        null,object-size  DblLnkLst_OffsetOf (dbllnklst.h:81), the hand-rolled
#                                            &((type *)0)->field offsetof, on every list walk; only
#                                            the unregistered fuzz_hgfs_server reaches this code
FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -O1 -fsanitize=fuzzer-no-link"
RELAXED=(
  "lib/dataMap:alignment"
  "lib/foundryMsg:alignment:foundryPropertyListCommon.lo"
  "lib/misc:pointer-overflow:codesetOld.lo"
  "lib/hgfsServer:null,object-size"
  "lib/hgfsServerPolicyGuest:null,object-size"
)
STAMP=mayhem-configure.cache
if [ ! -f configure ] || [ ! -f Makefile ] || [ "$(cat "$STAMP" 2>/dev/null)" != "$FLAGS ${RELAXED[*]}" ]; then
  autoreconf -i
  CC="$CC" CXX="$CXX" CFLAGS="$FLAGS -Wno-error" ./configure \
    --without-x --without-kernel-modules --without-icu --without-dnet --without-pam --without-fuse \
    --without-gtk3 --without-gtkmm3 \
    --disable-multimon --disable-resolutionkms --disable-containerinfo --disable-servicediscovery \
    --disable-libappmonitor --disable-tests --disable-docs --disable-vgauth \
    --enable-static --disable-shared
  # Flags changed (or first build): drop objects compiled with the old flags.
  make -C lib clean >/dev/null; make -C libvmtools clean >/dev/null
  echo "$FLAGS ${RELAXED[*]}" > "$STAMP"
fi
for r in "${RELAXED[@]}"; do
  IFS=: read -r dir checks objs <<<"$r"
  # shellcheck disable=SC2086 # $objs: the object list (empty = the whole directory)
  make -j"$MAYHEM_JOBS" -C "$dir" CFLAGS="$FLAGS -fno-sanitize=$checks -Wno-error" $objs
done
make -j"$MAYHEM_JOBS" -C lib
make -j"$MAYHEM_JOBS" -C libvmtools

LIBS=(
  "$OVT/lib/foundryMsg/.libs/libFoundryMsg.a"
  "$OVT/lib/hgfsServerManagerGuest/.libs/libHgfsServerManagerGuest.a"
  "$OVT/lib/hgfsServer/.libs/libHgfsServer.a"
  "$OVT/lib/hgfs/.libs/libHgfs.a"
  "$OVT/libvmtools/.libs/libvmtools.a"
)
CPPFLAGS=(-I"$OVT/lib/include" -I"$OVT/lib/jsmn" -DUSING_AUTOCONF=1 -DOPEN_VM_TOOLS -DNO_ICU
          -DVMX86_TOOLS -D_FILE_OFFSET_BITS=64 -D_DEFAULT_SOURCE -DNO_DNET=1)
SYSLIBS=($(pkg-config --libs glib-2.0 gmodule-2.0 gobject-2.0 libtirpc) -lpthread -ldl -lcrypt -lrt -lm)

# fuzz_hgfs_server is built but has no Mayhemfile yet: every HGFS packet shorter than 8 bytes
# reads past the packet (hgfsServerParameters.c:403 logs request->op before the size check), so
# libFuzzer aborts on its first 1-byte input and the target cannot pass a seedless smoke run. Run
# it by hand with the seeds from the PR (or once upstream fixes that read).
# fuzz_vix_decode is built but has no Mayhemfile either: VixMsgDecodeBuffer crashes on most inputs
# (mayhem/vix-decode/known-findings/ has a reproducer per bug), so every libFuzzer restart dies
# before Mayhem's 5-iteration probe. The property-list half of that code is the vix-proplist target.
# 2) LSan off at build time (leaks are not what this fleet fuzzes for), then each harness twice.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o /tmp/ovt_lsan_off.o
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o /tmp/ovt_standalone_main.o
# Panic()/VERIFY -> abort() instead of glib's SIGTRAP, which libFuzzer does not catch (panic_abort.c).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $(pkg-config --cflags glib-2.0) -c "$SRC/mayhem/panic_abort.c" -o /tmp/ovt_panic_abort.o
# The DnD/copy-paste codecs live in the dndcp plugin, which is C++/gtkmm and not built headless;
# compile its plain-C message/clipboard sources directly, with the project flags.
DND="$OVT/services/plugins/dndcp/dnd"
DNDOBJS=()
for f in dndClipboard dndCommon dndCPMsgV4 dndMsg dndLinux; do
  $CC $FLAGS -c "${CPPFLAGS[@]}" -I"$DND" $(pkg-config --cflags glib-2.0) "$DND/$f.c" -o "/tmp/ovt_dnd_$f.o"
  DNDOBJS+=("/tmp/ovt_dnd_$f.o")
done
# VGAuth's SAML token verifier. configure only builds vgauth with PAM (the service authenticates
# users), and only the SAML code is fuzzed, so its sources are compiled directly with the project
# flags, against apt's libxml2 + xmlsec1 (OpenSSL backend, linked directly: no crypto dlopen).
# The schemas it validates against are read at run time from the source tree.
VG="$OVT/vgauth"
VGCPP=(-I"$VG/public" -I"$VG/common" -I"$VG/serviceImpl" $(pkg-config --cflags glib-2.0 xmlsec1-openssl libxml-2.0 openssl))
VGOBJS=()
for f in serviceImpl/saml-xmlsec1 common/certverify common/prefs common/vmxlog common/vmxrpc \
         common/VGAuthLog common/VGAuthUtil; do
  o="/tmp/ovt_vg_$(basename "$f").o"
  $CC $FLAGS -c "${CPPFLAGS[@]}" "${VGCPP[@]}" "$VG/$f.c" -o "$o"
  VGOBJS+=("$o")
done
VGLIBS=($(pkg-config --libs xmlsec1-openssl libxml-2.0 openssl))
for h in "$SRC"/mayhem/harnesses/fuzz_*.c; do
  name="$(basename "$h" .c)"
  EXTRA=() ; HCPP=() ; HLIBS=()
  [ "$name" = fuzz_dndcp ] && EXTRA=("${DNDOBJS[@]}")
  if [ "$name" = fuzz_vgauth_saml ]; then
    EXTRA=("${VGOBJS[@]}") ; HLIBS=("${VGLIBS[@]}")
    HCPP=("${VGCPP[@]}" -DOVT_SAML_SCHEMA_DIR="\"$VG/serviceImpl/schemas\"")
  fi
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "${CPPFLAGS[@]}" -I"$DND" "${HCPP[@]}" $(pkg-config --cflags glib-2.0) "$h" -o "/tmp/ovt_$name.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "/tmp/ovt_$name.o" "${EXTRA[@]}" /tmp/ovt_lsan_off.o /tmp/ovt_panic_abort.o \
    -Wl,--start-group "${LIBS[@]}" -Wl,--end-group "${HLIBS[@]}" "${SYSLIBS[@]}" -o "$OUT/$name"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS /tmp/ovt_standalone_main.o "/tmp/ovt_$name.o" "${EXTRA[@]}" /tmp/ovt_lsan_off.o /tmp/ovt_panic_abort.o \
    -Wl,--start-group "${LIBS[@]}" -Wl,--end-group "${HLIBS[@]}" "${SYSLIBS[@]}" -o "$OUT/$name-standalone"
done

# 3) The known-answer oracle mayhem/test.sh runs (mayhem/oracle/ovt_oracle.c): plain main(), linked
#    against the same libraries. It is built with the project build's flags (sanitizers on, which
#    only adds checking) since configure builds lib/ once, in tree.
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -c "${CPPFLAGS[@]}" "${VGCPP[@]}" \
  -DOVT_SAML_SCHEMA_DIR="\"$VG/serviceImpl/schemas\"" \
  -DOVT_SAML_TOKEN="\"$SRC/mayhem/vgauth-saml/testsuite/smoke-token.xml\"" \
  "$SRC/mayhem/oracle/ovt_oracle.c" -o /tmp/ovt_oracle.o
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS /tmp/ovt_oracle.o "${VGOBJS[@]}" /tmp/ovt_lsan_off.o /tmp/ovt_panic_abort.o \
  -Wl,--start-group "${LIBS[@]}" -Wl,--end-group "${VGLIBS[@]}" "${SYSLIBS[@]}" -o "$OUT/ovt-oracle"
echo "built: $(ls "$OUT"/fuzz_* "$OUT"/ovt-oracle | tr '\n' ' ')"
