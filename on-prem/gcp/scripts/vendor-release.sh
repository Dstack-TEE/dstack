#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# VENDOR · run ONCE per workload release.
#
# Builds the component images, JWE-encrypts the workload image, pushes everything
# to $PUBREG, computes the two compose_hashes, registers the GLOBAL policy
# (os-image + kms-compose-hash) in the Authority, fills the deploy templates with
# the security pins (AUTHORITY_PUBKEY + image digests + app_id), and writes a
# release manifest that `vendor-add-tenant.sh` consumes per customer.
#
# Prereqs: Authority running (./deploy-authority.sh), config.env filled
# (PUBREG, IMAGE_KID, OS_IMAGE, APP_ID, WORKLOAD_SRC, WORKLOAD_NAME, AUTHORITY_URL,
# AUTHORITY_ADMIN_TOKEN). docker, skopeo, dstack-cloud, python3, openssl.
#
#   ./vendor-release.sh

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

GCP="$(cd "$HERE/.." && pwd)"
DC="${DSTACK_CLOUD:-dstack-cloud}"
A="${AUTHORITY_URL:?set AUTHORITY_URL}"
PUBREG="${PUBREG:?set PUBREG (vendor public registry, e.g. cr.kvin.wang)}"
IMAGE_KID="${IMAGE_KID:?set IMAGE_KID (global image key id, e.g. vendor-2026h1)}"
OS_VERSION="${OS_VERSION:?set OS_VERSION (dotted published name, e.g. dstack-cloud-nvidia-0.6.1)}"
OS_IMAGE="${OS_VERSION//./-}"   # local dir / app.json name (dots → dashes)
APP_ID="${APP_ID:?set APP_ID (workload app id, 40 hex)}"
WORKLOAD_SRC="${WORKLOAD_SRC:?set WORKLOAD_SRC (image to encrypt, e.g. traefik/whoami:latest)}"
WORKLOAD_NAME="${WORKLOAD_NAME:?set WORKLOAD_NAME (encrypted name, e.g. whoami-enc)}"
AUTH=(-H "Authorization: Bearer ${AUTHORITY_ADMIN_TOKEN:-}")

jqr() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }
digest_of() { skopeo inspect "docker://$1" --format '{{.Digest}}' | sed 's/^sha256://'; }

# ── 1. global image key (mint once; reuse on later releases) ───────────────────
c_step "global image key: $IMAGE_KID"
if ! curl -s "${AUTH[@]}" "$A/api/v1/admin/keys" \
     | python3 -c "import sys,json;ks=json.load(sys.stdin)['keys'];import os;
pub=next((k['pub_pem'] for k in ks if k['kid']=='$IMAGE_KID'),'')
open('$HERE/.image-key.pub.pem','w').write(pub) if pub else exit(1)" 2>/dev/null; then
    curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
        -d "{\"kid\":\"$IMAGE_KID\"}" "$A/api/v1/admin/keys" \
        | jqr pub_pem > "$HERE/.image-key.pub.pem"
    c_ok "minted $IMAGE_KID"
else
    c_ok "reusing existing $IMAGE_KID"
fi
[[ -s "$HERE/.image-key.pub.pem" ]] || c_die "could not obtain image public key"

# ── 2. authority signing pubkey (trust root pinned into the KMS compose) ───────
PUBKEY="$(curl -s "$A/api/v1/authority-pubkey" | jqr pubkey)"
[[ -n "$PUBKEY" ]] || c_die "authority unreachable at $A"
c_ok "AUTHORITY_PUBKEY=$PUBKEY"

# ── 3. build + push component images ───────────────────────────────────────────
c_step "build + push key-broker / launcher → $PUBREG"
( cd "$(cd "$ROOT/.." && pwd)" \
  && docker build -f on-prem/key-broker/Dockerfile -t "$PUBREG/key-broker:latest" . \
  && docker build -f on-prem/launcher/Dockerfile   -t "$PUBREG/launcher:latest"   . )
docker push "$PUBREG/key-broker:latest"
docker push "$PUBREG/launcher:latest"
# dstack-kms: the vendor's chosen dstack-kms image, retagged into $PUBREG. The
# official `dstacktee/dstack-kms` has NO `latest` tag (only versioned, e.g. 0.5.11)
# and the rpc-cert IP SAN needs a recent/mainline build — so this is configurable
# via DSTACK_KMS_SRC (defaults to one already in $PUBREG).
DSTACK_KMS_SRC="${DSTACK_KMS_SRC:-$PUBREG/dstack-kms:latest}"
if [[ "$DSTACK_KMS_SRC" != "$PUBREG/dstack-kms:latest" ]]; then
    docker pull "$DSTACK_KMS_SRC"
    docker tag  "$DSTACK_KMS_SRC" "$PUBREG/dstack-kms:latest"
    docker push "$PUBREG/dstack-kms:latest"
else
    c_ok "dstack-kms: using existing $PUBREG/dstack-kms:latest"
fi

# ── 4. JWE-encrypt the workload image → push (encryption needs only the pubkey) ─
c_step "JWE-encrypt $WORKLOAD_SRC → $PUBREG/$WORKLOAD_NAME"
skopeo copy --encryption-key "jwe:$HERE/.image-key.pub.pem" \
    "docker://$WORKLOAD_SRC" "docker://$PUBREG/$WORKLOAD_NAME:latest"

KB_DIGEST="$(digest_of "$PUBREG/key-broker:latest")"
KMS_DIGEST="$(digest_of "$PUBREG/dstack-kms:latest")"
LN_DIGEST="$(digest_of "$PUBREG/launcher:latest")"
WL_DIGEST="$(digest_of "$PUBREG/$WORKLOAD_NAME:latest")"
c_ok "digests: key-broker=$KB_DIGEST dstack-kms=$KMS_DIGEST launcher=$LN_DIGEST $WORKLOAD_NAME=$WL_DIGEST"

# ── 5. fill the deploy templates with the security pins ────────────────────────
c_step "fill deploy/kms + deploy/launcher with pins"
rm -rf "$GCP/deploy/kms" "$GCP/deploy/launcher"
cp -a "$GCP/deploy-templates/kms"      "$GCP/deploy/kms"
cp -a "$GCP/deploy-templates/workload" "$GCP/deploy/launcher"
sed -i -e "s|<PINNED_KEY_BROKER_DIGEST>|$KB_DIGEST|" \
       -e "s|<PINNED_DSTACK_KMS_DIGEST>|$KMS_DIGEST|" \
       -e "s|<PINNED_LITERAL_BASE64_AUTHORITY_PUBKEY>|$PUBKEY|" \
       "$GCP/deploy/kms/docker-compose.yaml"
sed -i -e "s|<PINNED_LAUNCHER_DIGEST>|$LN_DIGEST|" \
       -e "s|<WORKLOAD_IMAGE_NAME>|$WORKLOAD_NAME|" \
       -e "s|<WORKLOAD_APP_ID_40_HEX>|$APP_ID|" \
       "$GCP/deploy/launcher/docker-compose.yaml"
# app.json: app_id + os_image (GCP fields are filled by the operator)
python3 - "$GCP/deploy/launcher/app.json" "$APP_ID" "$OS_IMAGE" <<'PY'
import json,sys
f,app_id,osimg=sys.argv[1:4]
d=json.load(open(f)); d["app_id"]=app_id; d["os_image"]=osimg; json.dump(d,open(f,"w"),indent=2)
PY
python3 - "$GCP/deploy/kms/app.json" "$OS_IMAGE" <<'PY'
import json,sys
f,osimg=sys.argv[1:3]
d=json.load(open(f)); d["os_image"]=osimg; json.dump(d,open(f,"w"),indent=2)
PY

# ── 6. compute the two compose_hashes (sha256 of app-compose.json) ─────────────
c_step "compute compose_hashes"
"$DC" -C "$GCP/deploy/kms"      prepare >/dev/null
"$DC" -C "$GCP/deploy/launcher" prepare >/dev/null
KMS_COMPOSE_HASH="$(sha256sum "$GCP/deploy/kms/shared/app-compose.json"      | cut -d' ' -f1)"
LN_COMPOSE_HASH="$( sha256sum "$GCP/deploy/launcher/shared/app-compose.json" | cut -d' ' -f1)"
c_ok "kms_compose_hash=$KMS_COMPOSE_HASH  launcher_compose_hash=$LN_COMPOSE_HASH"

# ── 7. os_image_hash from the published release (no measure / no deploy) ────────
OS_HASH_FILE="$HOME/.dstack/images/$OS_IMAGE/auth_hash.txt"
[[ -f "$OS_HASH_FILE" ]] || { c_warn "pulling $OS_VERSION to read auth_hash.txt"; "$DC" pull "$OS_VERSION"; }
OS_IMAGE_HASH="$(cat "$OS_HASH_FILE")"
c_ok "os_image_hash=$OS_IMAGE_HASH"

# ── 8. register the GLOBAL policy (per-tenant app is done by vendor-add-tenant) ─
c_step "register global policy (os-image + kms-compose-hash)"
curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"hash\":\"$OS_IMAGE_HASH\"}"     "$A/api/v1/admin/os-images" >/dev/null
curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"hash\":\"$KMS_COMPOSE_HASH\"}"  "$A/api/v1/admin/kms-compose-hashes" >/dev/null
c_ok "registered"

# ── 9. release manifest (consumed by vendor-add-tenant.sh) ─────────────────────
cat > "$GCP/deploy/.release-manifest.env" <<EOF
# generated by vendor-release.sh — do not edit by hand
APP_ID=$APP_ID
LAUNCHER_COMPOSE_HASH=$LN_COMPOSE_HASH
WORKLOAD_IMAGE_DIGEST=sha256:$WL_DIGEST
KMS_COMPOSE_HASH=$KMS_COMPOSE_HASH
OS_IMAGE_HASH=$OS_IMAGE_HASH
AUTHORITY_PUBKEY=$PUBKEY
EOF
c_ok "wrote deploy/.release-manifest.env"

cat <<EOF

Release ready. Deliver to each operator:
  - the 4 images in $PUBREG (key-broker, dstack-kms, launcher, $WORKLOAD_NAME)
  - the filled templates: deploy/kms/ and deploy/launcher/ (compose pins)
  - AUTHORITY_PUBKEY (already pinned in the KMS compose)
Per customer, run:  ./vendor-add-tenant.sh <user_id>
EOF
