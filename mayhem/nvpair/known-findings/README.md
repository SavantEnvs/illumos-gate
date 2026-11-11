# Known findings in the nvlist code

Reproducers for genuine upstream defects found by `fuzz_nvlist`. They are kept here, not in `testsuite/`,
because every one of them aborts the target. Replay one with
`/mayhem/fuzz_nvlist-standalone mayhem/nvpair/known-findings/<name>/reproducer`.

- `native-string-array-oob-read/` — `nvpair_native_string_array()` (`usr/src/common/nvpair/nvpair.c:2941`)
  decoding a native-encoded `DATA_TYPE_STRING_ARRAY` calls `strlen()` on each element without checking that
  a terminating NUL lies inside the received buffer, so an unterminated last string reads past the heap
  buffer.
- `validate-string-oob-read/` — `i_get_value_size()` (`nvpair.c:1041`), reached from
  `i_validate_nvpair()` while unpacking, does `strlen()` of a `DATA_TYPE_STRING` value that the packed
  buffer need not terminate, reading past the end of the heap copy.
- `json-invalid-multibyte/` — `nvlist_print_json_string()` (`usr/src/lib/libnvpair/nvpair_json.c:97`) loops
  `while ((sz = mbrtowc(...)) > 0)`, which is also true for the error returns `(size_t)-1` and
  `(size_t)-2`; the body then does `input += sz`, stepping the pointer back one byte (before the start of
  the string when the bad byte is first). The `return (-1)` after the loop is unreachable for the same
  reason. Any string name or value with a byte the locale cannot decode triggers it (here the C locale and
  a byte >= 0x80).
