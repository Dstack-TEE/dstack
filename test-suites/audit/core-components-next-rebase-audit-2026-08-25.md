<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
# PR 841 next-rebase test audit (2026-08-25)

PR 841 was rebased from `af853d9144f4` onto `next` at `55021edbf8b2`. The intervening product changes were reviewed by merged-PR boundary and mapped to focused acceptance regressions.

## Focused regression boundaries

- Guest image identity and container runtime: PRs #1076, #1083, and #1092.
- Gateway registration, KV compatibility, deletion, readiness, health polling, removal errors, and metrics: PRs #1078, #1079, #1084, #1088, #1089, #1093, #1099, #1100, and #1102.
- VMM Gateway endpoint permutation: PR #1097.
- Structured RA-RPC errors and self-signed attested clients: PRs #1105 and #1106.
- TDX-only quote behavior and GPU evidence: PRs #1107, #1111, and #1112.
- Frozen v0 and byte-oriented v1 guest APIs and SDK compatibility: PRs #1116, #1118, #1121, #1122, and #1124.
- KMS image CA trust: PR #1128.
- DNS-01 authorization preservation, authoritative polling, fallback, and diagnostics: PRs #1129, #1130, and #1133.

Documentation-only, CI-only, dependency-pointer, lockfile, and refactoring changes remain covered by their existing build, lint, unit, compatibility, or source-derived cases. Newly introduced source paths are recorded in `source-inventory.json` and `source-coverage-map.json`. GPU-positive assertions remain hardware-gated, while CPU-only rejection rows are mandatory.
