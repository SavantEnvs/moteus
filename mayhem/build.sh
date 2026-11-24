#!/usr/bin/env bash
# mayhem/build.sh — build moteus's fuzz harnesses (sanitized, DWARF 3) and its host unit tests
# (normal flags). The fuzzed code is header-only (lib/cpp client library, fw/bissc_extract.h), so
# it is compiled into each harness TU with $SANITIZER_FLAGS.
set -euo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
: "${STANDALONE_FUZZ_MAIN:=/opt/mayhem/StandaloneFuzzTargetMain.c}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/out"          # gitignored build dir (mayhem/.gitignore)
mkdir -p "$OUT/obj"

CXXSTD="-std=c++17"
INCS="-I$SRC/lib/cpp/mjbots/moteus -I$SRC"

# Shared objects: LSan-off hook and the run-once standalone driver (as C, so its
# LLVMFuzzerTestOneInput reference keeps C linkage).
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/obj/lsan_off.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/obj/standalone_main.o"

# mjlib (firmware support library, pre-fetched by the Dockerfile at upstream's bazel pin): the
# micro CommandManager/PersistentConfig/serializable_handler sources fuzz_motor_position_conf
# drives. They parse the fuzzed text, so they get $SANITIZER_FLAGS too. mjlib needs C++20.
MJLIB="${MJLIB:-/opt/toolchains/deps/mjlib-c367638ec1e9f97e3affc83b739156ceb95f026b/src}"
[ -d "$MJLIB/mjlib" ] || { echo "mjlib source missing at $MJLIB" >&2; exit 1; }
MJLIB_OBJS=()
for f in micro/command_manager micro/persistent_config micro/pool_ptr micro/stream_pipe \
         micro/telemetry_manager micro/serializable_handler micro/error_code \
         micro/callback_table micro/error base/assert; do
  o="$OUT/obj/mjlib_${f//\//_}.o"
  $CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link -I"$MJLIB" \
      -c "$MJLIB/mjlib/$f.cc" -o "$o"
  MJLIB_OBJS+=("$o")
done

h=fuzz_motor_position_conf
FW_INCS="-I$SRC -I$MJLIB"
$CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $FW_INCS \
    -c "$SRC/mayhem/harnesses/$h.cc" -o "$OUT/obj/$h.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/$h.o" "${MJLIB_OBJS[@]}" \
    "$OUT/obj/lsan_off.o" -o "$SRC/$h"
# Standalone: the same objects (SanCov hooks resolve to weak no-ops without libFuzzer).
$CXX -std=c++20 $SANITIZER_FLAGS $DEBUG_FLAGS $FW_INCS \
    -c "$SRC/mayhem/harnesses/$h.cc" -o "$OUT/obj/$h.standalone.o"
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj/$h.standalone.o" "${MJLIB_OBJS[@]}" \
    "$OUT/obj/standalone_main.o" "$OUT/obj/lsan_off.o" -o "$SRC/$h-standalone"

for h in fuzz_protocol_parse fuzz_fdcanusb_transport fuzz_bissc_extract; do
  # The fuzzed code is header-only, so the harness TU IS the project code: compile it with SanCov
  # (-fsanitize=fuzzer-no-link) for the libFuzzer binary, and without it for the standalone one.
  $CXX $CXXSTD $SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link $INCS \
      -c "$SRC/mayhem/harnesses/$h.cc" -o "$OUT/obj/$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "$OUT/obj/$h.o" "$OUT/obj/lsan_off.o" \
      -pthread -o "$SRC/$h"
  $CXX $CXXSTD $SANITIZER_FLAGS $DEBUG_FLAGS $INCS \
      -c "$SRC/mayhem/harnesses/$h.cc" -o "$OUT/obj/$h.standalone.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS "$OUT/obj/$h.standalone.o" "$OUT/obj/standalone_main.o" \
      "$OUT/obj/lsan_off.o" -pthread -o "$SRC/$h-standalone"
done

# Upstream's own host unit tests (Boost.Test), NORMAL flags: the C++ client library suite and the
# BiSS-C extractor suite (same sources bazel's //lib/cpp/... and //fw:test use).
# moteus_test.cc uses std::optional without including <optional> (bazel's toolchain pulls it in
# transitively); force-include it rather than edit upstream.
$CXX $CXXSTD -O1 $COVERAGE_FLAGS -DBOOST_TEST_DYN_LINK -include optional -I"$SRC/lib/cpp" \
    lib/cpp/mjbots/moteus/test/test_main.cc \
    lib/cpp/mjbots/moteus/test/moteus_protocol_test.cc \
    lib/cpp/mjbots/moteus/test/moteus_test.cc \
    -lboost_unit_test_framework -pthread -o "$OUT/cpp_test"
# Firmware suites: BiSS-C extractor and MotorPosition (the latter against mjlib's micro test
# fixtures, so mjlib is compiled again here with normal flags; mjlib needs C++20).
MJLIB_TEST_OBJS=()
for f in micro/command_manager micro/persistent_config micro/pool_ptr micro/stream_pipe \
         micro/telemetry_manager micro/serializable_handler micro/error_code \
         micro/callback_table micro/error base/assert; do
  o="$OUT/obj/mjlib_test_${f//\//_}.o"
  $CXX -std=c++20 -O1 $COVERAGE_FLAGS -I"$MJLIB" -c "$MJLIB/mjlib/$f.cc" -o "$o"
  MJLIB_TEST_OBJS+=("$o")
done
$CXX -std=c++20 -O1 $COVERAGE_FLAGS -DBOOST_TEST_DYN_LINK -I"$SRC" -I"$MJLIB" \
    fw/test/test_main.cc fw/test/bissc_extract_test.cc fw/test/motor_position_test.cc \
    "${MJLIB_TEST_OBJS[@]}" -lboost_unit_test_framework -o "$OUT/fw_test"
