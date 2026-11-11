# Known findings in the SMBIOS parser

Reproducers for genuine upstream defects found by `fuzz_smbios`. They are kept here, not in
`testsuite/`, because every one of them aborts the target. Replay one with
`/mayhem/fuzz_smbios-standalone mayhem/smbios/known-findings/<name>/reproducer`.

- `table-nentries-oob-read/` — `smbios_table_nentries()` (`usr/src/common/smbios/smb_open.c:201`) walks the
  structure table of an SMBIOS 3.0 entry point (which has no structure count) and reads
  `hdr->smbh_len` and the string-set bytes without checking that a full header (or the string area) lies
  inside `smbe_stlen`. A table whose last structure is truncated reads past the heap buffer.
- `chassis-elts-heap-overflow/` — `smbios_info_chassis_elts()` (`usr/src/common/smbios/smb_info.c:701-718`)
  allocates `cm * cn` bytes (3 bytes per contained-element record, the on-disk size) but fills `cn`
  `smbios_chassis_entry_t` entries (4 bytes each), so any chassis structure with contained elements
  overflows the heap buffer by `cn` bytes.
