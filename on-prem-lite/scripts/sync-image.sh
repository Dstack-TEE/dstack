#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Sync a container image from an external registry into the customer's GCP
# Artifact Registry, so no-internet CVMs can pull it over Private Google Access.
# Uses skopeo (copies by digest → integrity-preserving; works for plaintext AND
# ocicrypt-encrypted images, which are copied verbatim).
#
#   ./sync-image.sh <src-ref> [<dest-repo-path>]
#
#   src-ref         e.g. cr.kvin.wang/lite-launcher:latest  (or @sha256:…)
#   dest-repo-path  e.g. lite-launcher:latest  (defaults to the src path's last
#                   component). Pushed to:
#                   <AR_LOCATION>-docker.pkg.dev/<AR_PROJECT>/<AR_REPO>/<dest>
#
# Config (config.env or env): AR_LOCATION, AR_PROJECT, AR_REPO,
#   SRC_AUTHFILE (docker config for the source registry, optional).

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

AR_LOCATION="${AR_LOCATION:-us-central1}"
AR_PROJECT="${AR_PROJECT:-$GCP_PROJECT}"
AR_REPO="${AR_REPO:-dstack-private}"
AR_HOST="${AR_LOCATION}-docker.pkg.dev"
AR_BASE="${AR_HOST}/${AR_PROJECT}/${AR_REPO}"

SRC="${1:?usage: sync-image.sh <src-ref> [<dest-repo-path>]}"
DEST_PATH="${2:-$(basename "$SRC")}"
DEST="${AR_BASE}/${DEST_PATH}"

# AR auth: short-lived OAuth token from the active gcloud identity.
TOKEN="$(gcloud auth print-access-token 2>/dev/null)" || c_die "gcloud auth print-access-token failed"
DEST_CREDS="oauth2accesstoken:${TOKEN}"

SRC_AUTH_ARGS=()
[[ -n "${SRC_AUTHFILE:-}" ]] && SRC_AUTH_ARGS=(--src-authfile "$SRC_AUTHFILE")

c_step "sync  ${SRC}  →  ${DEST}"
skopeo copy --all "${SRC_AUTH_ARGS[@]}" --dest-creds "$DEST_CREDS" \
    "docker://${SRC}" "docker://${DEST}"

DIGEST="$(skopeo inspect --creds "$DEST_CREDS" --format '{{.Digest}}' "docker://${DEST}" 2>/dev/null)"
c_ok "synced. pull as:  ${DEST}@${DIGEST}"
echo "$DEST@$DIGEST"
