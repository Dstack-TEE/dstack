#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Shared helpers for the on-prem GCP deploy/provision scripts.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"        # on-prem/ (these scripts live in gcp/scripts/)

# Load config.env (next to the scripts) if present.
if [[ -f "$HERE/config.env" ]]; then
    # shellcheck disable=SC1091
    source "$HERE/config.env"
fi

c_step()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }
c_ok()    { printf '  \033[0;32m✓ %s\033[0m\n' "$*"; }
c_warn()  { printf '  \033[1;33m%s\033[0m\n' "$*"; }
c_die()   { printf '  \033[0;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# Run a command inside the KMS CVM over IAP (no public IP, no in-CVM sshd config
# needed beyond the dstack persistent sshd). $1 = remote command.
kms_ssh() {
    gcloud compute ssh "root@${KMS_VM}" \
        --project="$GCP_PROJECT" --zone="$GCP_ZONE" --tunnel-through-iap \
        --ssh-flag="-i ${SSH_KEY}" --command="$1" 2>&1 \
        | grep -v "NumPy\|tunnel-through-iap\|cloud.google\|^WARNING\|^$" || true
}

# Copy a local file to the CVM (base64 over the IAP ssh channel; gcloud scp's
# --scp-flag handles -i differently across versions, so we avoid it).
kms_put() {  # $1=local file  $2=remote path
    local b64; b64="$(base64 -w0 "$1")"
    kms_ssh "echo '$b64' | base64 -d > '$2'"
}
