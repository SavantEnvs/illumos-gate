#!/usr/bin/env bash
#
# mayhem/test.sh — known-answer tests of three illumos components, all built by mayhem/build.sh with
# normal flags. Each check compares the program's real output with expected values written down in the
# repo, so a neutered or no-op binary prints nothing and fails.
#   smbios   smbios_kat decodes a hand-built SMBIOS table (smbios/kat/table.bin; gen_fixtures.py shows the
#            field values) and prints what it parsed; every line must equal smbios/kat/expected.txt:
#            vendor/version strings, ROM size, UUID, chassis type and OEM word, DIMM sizes, ...
#   nvpair   nvpair_kat unpacks a packed nvlist in both encodings (XDR and native) holding one pair of
#            every scalar/array type plus nested lists; both dumps must equal nvpair/kat/expected.txt.
#   diagcode upstream's own diagcode_test runs the #TEST: cases embedded in libdiagcode's tests/*.dict
#            (e.g. key2code "fault.z.one" -> "SAMPLE1-9YYY-X6") and must print its "All tests passed"
#            line; a copy of SAMPLE1 with one wrong expected code must make it fail.
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

# compare "$2" (a command's output) with the golden lines in "$3"; counts one test per line
check_lines() {
  local what="$1" actual="$2" expected="$3" n=0 got want
  while IFS= read -r want; do
    n=$((n + 1))
    got="$(printf '%s\n' "$actual" | sed -n "${n}p")"
    if [ "$got" = "$want" ]; then
      passed=$((passed + 1))
    else
      failed=$((failed + 1))
      echo "FAIL $what line $n"; echo "  want: $want"; echo "  got:  $got"
    fi
  done < "$expected"
  # no extra output beyond the golden lines
  if [ "$(printf '%s\n' "$actual" | wc -l)" -ne "$n" ]; then
    failed=$((failed + 1))
    echo "FAIL $what: output has $(printf '%s\n' "$actual" | wc -l) lines, expected $n"
  fi
}

need() { [ -x "$1" ] || { echo "missing $1 — mayhem/build.sh should have built it" >&2; emit_ctrf "illumos-kat" 0 1 0; exit 1; }; }

passed=0
failed=0

need mayhem/build/test/smbios_kat
check_lines smbios "$(mayhem/build/test/smbios_kat mayhem/smbios/kat/table.bin 2>&1)" mayhem/smbios/kat/expected.txt

need mayhem/build/test/nvpair_kat
for enc in xdr native; do
  check_lines "nvpair-$enc" "$(mayhem/build/test/nvpair_kat mayhem/nvpair/kat/full-$enc.bin 2>&1)" mayhem/nvpair/kat/expected.txt
done

need mayhem/build/test/diagcode_test
TESTS=usr/src/lib/fm/libdiagcode/common/tests
out="$(mayhem/build/test/diagcode_test "$TESTS" 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && [ "$out" = "diagcode_test: All tests passed." ]; then
  passed=$((passed + 1))
else
  failed=$((failed + 1)); echo "FAIL diagcode_test (rc=$rc): $out"
fi
# the driver must also notice a wrong answer: SAMPLE1 with one expected code changed
bad="$(mktemp -d "${TMPDIR:-/tmp}/dctest.XXXXXX")"
sed 's/SAMPLE1-9YYY-X6/SAMPLE1-9YYY-X7/' "$TESTS/SAMPLE1.dict" > "$bad/SAMPLE1.dict"
if grep -q 'SAMPLE1-9YYY-X7' "$bad/SAMPLE1.dict" && ! mayhem/build/test/diagcode_test "$bad" >/dev/null 2>&1; then
  passed=$((passed + 1))
else
  failed=$((failed + 1)); echo "FAIL diagcode_test accepted a dictionary with a wrong expected code"
fi
rm -rf "$bad"

emit_ctrf "illumos-kat" "$passed" "$failed" 0
