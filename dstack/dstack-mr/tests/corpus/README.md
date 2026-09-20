<!--
SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>

SPDX-License-Identifier: Apache-2.0
-->

# Parser corpus

Byte patterns that broke, or could break, a parser in `dstack-mr`. Each one is
read by a table-driven test in the matching `proptests` module, which asserts
only that the parser returns — `Ok` or `Err` — within
`prop_harness::CASE_BUDGET` and does not panic. Release binaries are built
`panic = "abort"`, so a panic in any of these aborts `dstack-verifier` or
`dstack-kms` rather than failing one measurement.

The corpus exists so each pattern stays a regression test whether or not the
bounded random search in the same module rediscovers it. The search runs a
fixed number of cases from a fixed seed; these files do not depend on either.

All offsets below are little-endian, matching the on-wire layouts.

## `tdvf/` — `Tdvf::parse`, `compute_mrtd`, `measure_td_hob`

| File | Pattern |
| --- | --- |
| `guid_table_entry_len_0.bin` | A GUIDed-table entry whose length field is `0`. The backwards walk subtracts the length from its cursor, so the cursor never moves. |
| `guid_table_entry_len_17.bin` | An entry length of `17`, one below the 18-byte length+GUID header the entry must contain. |
| `section_data_past_blob.bin` | `ATTRIBUTE_MR_EXTEND` with `memory_data_size = 0x100000` over a `0x1000`-byte body. MR.EXTEND hashes `memory_data_size` bytes from `data_offset`, not `raw_data_size`. |
| `memory_data_size_1tib.bin` | `memory_data_size = 0x1000_0000_0000`. That is 2^36 measured pages, with nothing between the file and the hash loop. |
| `memory_address_wraps.bin` | `memory_address = 0xffff_ffff_ffff_f000` with `memory_data_size = 0x2000`, so `memory_address + page * PAGE_SIZE` leaves the address space. |
| `num_sections_u32_max.bin` | `num_sections = 0xffff_ffff` over a table holding 200 records. The count is a raw `u32`; the table it describes need not be in the image. |
| `data_offset_size_overflow.bin` | `data_offset` and `memory_data_size` chosen so their sum overflows `u64` before either is compared against the image length. |

## `td_hob_witness/` — `measure_td_hob_from_witness_data`

| File | Pattern |
| --- | --- |
| `ranges_50000.bin` | 50 000 accepted ranges. `MemoryAcceptor::accept` rebuilds and re-sorts the whole range vector per call, so the decode is quadratic in the range count; a range costs about two bytes of witness. The file is large because a truncated copy does not reproduce it — the decode has to reach the ranges. |
| `page_arithmetic_overflow.bin` | `base_page`, `start_page_delta` and `page_count` all at `u64::MAX`, exercising the `base_page + start_page_delta` and `start + len` adds. |

## `pe/` — `kernel_authenticode_sha384`, `patched_kernel_authenticode_sha384`

| File | Pattern |
| --- | --- |
| `size_of_headers_ffff_fff0.bin` | `SizeOfHeaders = 0xffff_fff0`, far past the end of the image, used directly as a slice bound. |
| `size_of_headers_0.bin` | `SizeOfHeaders = 0`, before the certificate directory the header region contains, so the hashed slice would start after it ends. |
| `len_lfanew_plus_88.bin` | A file of exactly `lfanew + 88` bytes: long enough to read `SizeOfHeaders`, too short to hold the certificate directory hashed before it. |
| `section_past_image.bin` | A section whose `PointerToRawData`/`SizeOfRawData` run past the image, plus a certificate table claiming `0xffff_ffff` trailing bytes. |

## `ovmf/` — the OVMF footer and SEV metadata parsers

| File | Pattern |
| --- | --- |
| `footer_entry_size_0.bin` | A footer entry whose size field is `0`, the same non-advancing walk as the TDVF table. |
| `footer_total_size_0.bin` | A footer `total_size` smaller than the 18-byte footer entry it must contain. |
| `metadata_offset_past_image.bin` | A `SEV_META_DATA` entry whose metadata offset-from-end is `0xffff_ffff`. |
| `metadata_num_items_u32_max.bin` | A well-formed footer pointing at an `ASEV` block declaring `0xffff_ffff` sections. |
