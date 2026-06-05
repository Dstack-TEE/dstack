#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared helpers for the on-prem-lite deploy/license scripts.
#
# Forked from on-prem/gcp/scripts/lib.sh, trimmed for the lite profile: ONE CVM
# (the workload launcher), no KMS CVM, no key-broker, no static-IP/cert-SAN, no
# SWP egress proxy. ROOT points at the on-prem-lite/ dir so the scripts find
# authority/ and cli/.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"           # on-prem-lite/ (these scripts live in scripts/)

# Load config.env (next to the scripts) if present.
if [[ -f "$HERE/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$HERE/config.env"
fi

c_step()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
c_ok()    { printf '  \033[0;32m✓ %s\033[0m\n' "$*"; }
c_warn()  { printf '  \033[1;33m%s\033[0m\n' "$*"; }
c_die()   { printf '  \033[0;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }
