#!/usr/bin/env bash
#
# mayhem/build.sh — builds three self-contained illumos parsers for Linux and wraps each in a libFuzzer
# harness: the SMBIOS table parser (usr/src/common/smbios, shared by the kernel and libsmbios), the nvlist
# unpacker (usr/src/common/nvpair + libnvpair) and the FMA diagcode dictionary reader (libdiagcode).
# illumos itself needs its own build system, so only those few sources are compiled here, against shim
# headers (mayhem/<x>/shim: glibc stand-ins for the illumos <sys/...> headers the sources use).
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

SRC="${SRC:-/mayhem}"
cd "$SRC"

B="$SRC/mayhem/build"
M="$SRC/mayhem/smbios"
LIBSRC=(
  usr/src/common/smbios/smb_info.c
  usr/src/common/smbios/smb_open.c
  usr/src/common/smbios/smb_error.c
  usr/src/lib/libsmbios/common/smb_subr.c
)

# <sys/smbios.h> and <sys/smbios_impl.h> live in the kernel headers; expose just those two under a
# private include root so the shim's <sys/types.h> et al. are what the parser sees for everything else.
mkdir -p "$B/inc/sys"
ln -sfn "$SRC/usr/src/uts/common/sys/smbios.h" "$B/inc/sys/smbios.h"
ln -sfn "$SRC/usr/src/uts/common/sys/smbios_impl.h" "$B/inc/sys/smbios_impl.h"
INC=(-I "$M/shim" -I "$B/inc")

# 1) Sanitized parser (the fuzzed code), with SanCov so Mayhem sees its edges.
mkdir -p "$B/fuzz"
objs=()
for f in "${LIBSRC[@]}"; do
  o="$B/fuzz/$(basename "$f" .c).o"
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -w -fsanitize=fuzzer-no-link "${INC[@]}" -c "$SRC/$f" -o "$o"
  objs+=("$o")
done

# 2) Harness: libFuzzer binary + standalone run-once reproducer; LeakSanitizer is switched off at build time.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$B/fuzz/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -w -fsanitize=fuzzer-no-link "${INC[@]}" -c "$M/fuzz_smbios.c" -o "$B/fuzz/fuzz_smbios.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/fuzz/fuzz_smbios.o" "${objs[@]}" "$B/fuzz/lsan_off.o" \
    -o "$SRC/fuzz_smbios"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o "$B/fuzz/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/standalone_main.o" "$B/fuzz/fuzz_smbios.o" "${objs[@]}" "$B/fuzz/lsan_off.o" \
    -o "$SRC/fuzz_smbios-standalone"

# 3) Known-answer probe for test.sh: the same parser, normal flags, no sanitizers.
mkdir -p "$B/test"
tobjs=()
for f in "${LIBSRC[@]}" mayhem/smbios/smbios_kat.c; do
  o="$B/test/$(basename "$f" .c).o"
  $CC -O2 -w $COVERAGE_FLAGS "${INC[@]}" -c "$SRC/$f" -o "$o"
  tobjs+=("$o")
done
$CC $COVERAGE_FLAGS "${tobjs[@]}" -o "$B/test/smbios_kat"

# ---------------------------------------------------------------------------------------------------
# nvlist: usr/src/common/nvpair (pack/unpack, the kernel's code) + libnvpair (print, JSON). The shim
# supplies the illumos-only headers; XDR comes from libtirpc.
# ---------------------------------------------------------------------------------------------------
N="$SRC/mayhem/nvpair"
NVSRC=(
  usr/src/common/nvpair/nvpair.c
  usr/src/common/nvpair/fnvpair.c
  usr/src/lib/libnvpair/nvpair_alloc_system.c
  usr/src/lib/libnvpair/libnvpair.c
  usr/src/lib/libnvpair/nvpair_json.c
)
mkdir -p "$B/nvinc/sys"
ln -sfn "$SRC/usr/src/uts/common/sys/nvpair.h" "$B/nvinc/sys/nvpair.h"
ln -sfn "$SRC/usr/src/uts/common/sys/nvpair_impl.h" "$B/nvinc/sys/nvpair_impl.h"
ln -sfn "$SRC/usr/src/lib/libnvpair/libnvpair.h" "$B/nvinc/libnvpair.h"
NVINC=(-I "$N/shim" -I "$B/nvinc" -I /usr/include/tirpc)
NVDEF=(-DTEXT_DOMAIN=\"SUNW_OST_OSLIB\")
# libtirpc is linked dynamically: ASan intercepts xdrmem_create() and resolves the real one with dlsym,
# which finds nothing when libtirpc.a is linked statically (the interceptor then calls NULL).
TIRPC=(-ltirpc)

# nvlist_size()/nvlist_pack() size a list by running the encoder over a NULL buffer, so every sizing call
# computes "NULL + sizeof (nvs_header_t)" (nvs_native() in nvpair.c). That is benign pointer arithmetic
# that UBSan's pointer-overflow check flags on any list. nvpair_native_embedded() likewise writes through an
# "nvlist_t *" into the packed buffer and says in a comment that the address may not be aligned, which
# trips the alignment check on every list holding a nested list. Only those two checks are relaxed, and
# only for nvpair.c; ASan and the rest of UBSan stay halting.
mkdir -p "$B/nvfuzz"
nobjs=()
for f in "${NVSRC[@]}"; do
  o="$B/nvfuzz/$(basename "$f" .c).o"
  relax=()
  [ "$(basename "$f")" = nvpair.c ] && relax=(-fno-sanitize=pointer-overflow,alignment)
  $CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -w "${relax[@]}" -fsanitize=fuzzer-no-link "${NVDEF[@]}" "${NVINC[@]}" -c "$SRC/$f" -o "$o"
  nobjs+=("$o")
done
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -w -fsanitize=fuzzer-no-link "${NVINC[@]}" -c "$N/fuzz_nvlist.c" -o "$B/nvfuzz/fuzz_nvlist.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/nvfuzz/fuzz_nvlist.o" "${nobjs[@]}" "$B/fuzz/lsan_off.o" \
    "${TIRPC[@]}" -o "$SRC/fuzz_nvlist"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/standalone_main.o" "$B/nvfuzz/fuzz_nvlist.o" "${nobjs[@]}" "$B/fuzz/lsan_off.o" \
    "${TIRPC[@]}" -o "$SRC/fuzz_nvlist-standalone"

mkdir -p "$B/test"
tobjs=()
for f in "${NVSRC[@]}" mayhem/nvpair/nvpair_kat.c; do
  o="$B/test/nv_$(basename "$f" .c).o"
  $CC -O2 -w $COVERAGE_FLAGS "${NVDEF[@]}" "${NVINC[@]}" -c "$SRC/$f" -o "$o"
  tobjs+=("$o")
done
$CC $COVERAGE_FLAGS "${tobjs[@]}" "${TIRPC[@]}" -o "$B/test/nvpair_kat"

# ---------------------------------------------------------------------------------------------------
# diagcode: libdiagcode's dictionary reader (one self-contained file). Upstream's own unit-test driver
# (diagcode_test.c) is built with normal flags for test.sh.
# ---------------------------------------------------------------------------------------------------
mkdir -p "$B/dcinc/fm"
ln -sfn "$SRC/usr/src/lib/fm/libdiagcode/common/diagcode.h" "$B/dcinc/fm/diagcode.h"
DCINC=(-I "$SRC/mayhem/diagcode/shim" -I "$B/dcinc")
DCSRC=usr/src/lib/fm/libdiagcode/common/diagcode.c

mkdir -p "$B/dcfuzz"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -w -fsanitize=fuzzer-no-link "${DCINC[@]}" -c "$SRC/$DCSRC" -o "$B/dcfuzz/diagcode.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -O1 -w -fsanitize=fuzzer-no-link "${DCINC[@]}" -c "$SRC/mayhem/diagcode/fuzz_diagcode.c" \
    -o "$B/dcfuzz/fuzz_diagcode.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$B/dcfuzz/fuzz_diagcode.o" "$B/dcfuzz/diagcode.o" "$B/fuzz/lsan_off.o" \
    -o "$SRC/fuzz_diagcode"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS "$B/fuzz/standalone_main.o" "$B/dcfuzz/fuzz_diagcode.o" "$B/dcfuzz/diagcode.o" "$B/fuzz/lsan_off.o" \
    -o "$SRC/fuzz_diagcode-standalone"

$CC -O2 -w $COVERAGE_FLAGS "${DCINC[@]}" "$SRC/$DCSRC" "$SRC/usr/src/lib/fm/libdiagcode/common/diagcode_test.c" \
    -o "$B/test/diagcode_test"
