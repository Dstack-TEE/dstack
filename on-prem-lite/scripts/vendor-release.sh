#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# VENDOR · run ONCE per workload release.
#
# Mints the global image key, builds/pushes the lite-launcher, JWE-encrypts the
# workload image, creates the tenant + app on the authority, computes the
# launcher compose_hash, registers the launcher compose_hash + workload digest as
# policy, fills the deploy template with the security pins (lite-launcher digest +
# AUTHORITY_PUBKEY + app_id, all MEASURED into the launcher's compose_hash), and
# writes a release manifest the operator consumes.
#
# vendor==operator simplification (this test): the registered workload image ref
# is derived from the operator's AR (AR_LOCATION/AR_PROJECT/AR_REPO). A true
# vendor/operator split would resolve the registry operator-side instead.
#
# Prereqs: authority running (./deploy-authority.sh), config.env filled
# (AUTHORITY_URL, AUTHORITY_ADMIN_TOKEN, PUBREG, IMAGE_KID, WORKLOAD_SRC,
# WORKLOAD_NAME, USER_ID, OS_VERSION, AR_*). docker, skopeo, dstack-cloud, python3.
#
#   ./vendor-release.sh

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DC="${DSTACK_CLOUD:-dstack-cloud}"
A="${AUTHORITY_URL:?set AUTHORITY_URL}"
PUBREG="${PUBREG:?set PUBREG (vendor public registry, e.g. cr.kvin.wang)}"
IMAGE_KID="${IMAGE_KID:?set IMAGE_KID (global image key id, e.g. vendor-2026h1)}"
OS_VERSION="${OS_VERSION:?set OS_VERSION (dotted published name, e.g. dstack-cloud-nvidia-0.6.1)}"
OS_IMAGE="${OS_VERSION//./-}"   # app.json os_image (dots → dashes)
WORKLOAD_SRC="${WORKLOAD_SRC:?set WORKLOAD_SRC (image to encrypt, e.g. traefik/whoami:latest)}"
WORKLOAD_NAME="${WORKLOAD_NAME:?set WORKLOAD_NAME (encrypted name, e.g. whoami-enc)}"
USER_ID="${USER_ID:?set USER_ID (tenant id)}"
# vendor==operator: the registered workload image ref is the operator AR path.
REGION="${GCP_ZONE%-*}"
AR="${AR_LOCATION:-$REGION}-docker.pkg.dev/${AR_PROJECT:-$GCP_PROJECT}/${AR_REPO:-dstack-private}"
AUTH=(-H "Authorization: Bearer ${AUTHORITY_ADMIN_TOKEN:-}")

jqr() { python3 -c "import sys,json;print(json.load(sys.stdin).get('$1',''))"; }
digest_of() { skopeo inspect "docker://$1" --format '{{.Digest}}' | sed 's/^sha256://'; }

# ── 1. authority signing pubkey (trust root pinned into the launcher compose) ──
PUBKEY="$(curl -s "$A/api/v1/authority-pubkey" | jqr pubkey)"
[[ -n "$PUBKEY" ]] || c_die "authority unreachable at $A"
c_ok "AUTHORITY_PUBKEY=$PUBKEY"

# ── 2. global image key (mint once; reuse on later releases) ───────────────────
c_step "global image key: $IMAGE_KID"
if ! curl -s "${AUTH[@]}" "$A/api/v1/admin/keys" \
     | python3 -c "import sys,json;ks=json.load(sys.stdin)['keys']
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

# ── 3. lite-launcher image → $PUBREG ───────────────────────────────────────────
# Either PULL a prebuilt source (set LITE_LAUNCHER_SRC) and retag into $PUBREG, or
# BUILD from on-prem-lite/launcher/Dockerfile. The launcher enforces the License
# gates, so a real release should build its own and pin its own digest.
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
LL_TGT="$PUBREG/lite-launcher:latest"
if [[ -n "${LITE_LAUNCHER_SRC:-}" && "$LITE_LAUNCHER_SRC" != "$LL_TGT" ]]; then
    c_step "pull prebuilt lite-launcher ← $LITE_LAUNCHER_SRC (skip build)"
    docker pull "$LITE_LAUNCHER_SRC"; docker tag "$LITE_LAUNCHER_SRC" "$LL_TGT"; docker push "$LL_TGT"
elif [[ -n "${LITE_LAUNCHER_SRC:-}" ]]; then
    c_ok "lite-launcher: using existing $LL_TGT"
else
    c_step "build lite-launcher → $PUBREG"
    docker build -f "$ROOT/launcher/Dockerfile" -t "$LL_TGT" "$REPO_ROOT"
    docker push "$LL_TGT"
fi

# ── 4. JWE-encrypt the workload image → push (encryption needs only the pubkey) ─
c_step "JWE-encrypt $WORKLOAD_SRC → $PUBREG/$WORKLOAD_NAME"
skopeo copy --encryption-key "jwe:$HERE/.image-key.pub.pem" \
    "docker://$WORKLOAD_SRC" "docker://$PUBREG/$WORKLOAD_NAME:latest"

# ── 5. create tenant (tolerate 409) ────────────────────────────────────────────
c_step "create tenant $USER_ID"
TENANT_RESP="$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"tenant_id\":\"$USER_ID\"}" "$A/api/v1/admin/tenants")"
API_KEY="$(printf '%s' "$TENANT_RESP" | jqr api_key)"
if [[ -n "$API_KEY" ]]; then
    c_ok "tenant $USER_ID created — api_key=$API_KEY"
else
    c_ok "tenant $USER_ID already exists (api_key not re-issued; reuse the original)"
fi

# ── 6. create app (authority assigns app_id if APP_ID blank) ────────────────────
c_step "create app under $USER_ID"
APP_RESP="$(curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "$(python3 -c "import json,os;print(json.dumps({'app_id': os.environ.get('APP_ID') or None}))")" \
    "$A/api/v1/admin/tenants/$USER_ID/apps")"
APP_ID="$(printf '%s' "$APP_RESP" | jqr app_id)"
[[ -n "$APP_ID" ]] || c_die "authority did not return an app_id: $APP_RESP"
c_ok "app_id=$APP_ID"

# ── 7. compute digests ─────────────────────────────────────────────────────────
LITE_LAUNCHER_DIGEST="$(digest_of "$LL_TGT")"
WL_DIGEST="$(digest_of "$PUBREG/$WORKLOAD_NAME:latest")"
c_ok "digests: lite-launcher=$LITE_LAUNCHER_DIGEST $WORKLOAD_NAME=$WL_DIGEST"

# ── 8. fill the deploy template with the security pins (MEASURED values) ────────
c_step "fill deploy/workload with pins (lite-launcher digest + AUTHORITY_PUBKEY + app_id)"
rm -rf "$ROOT/deploy/workload"
mkdir -p "$ROOT/deploy"
cp -a "$ROOT/deploy-templates/workload" "$ROOT/deploy/workload"
sed -i -e "s|<PINNED_LITE_LAUNCHER_DIGEST>|$LITE_LAUNCHER_DIGEST|" \
       -e "s|<PINNED_LITERAL_BASE64_AUTHORITY_PUBKEY>|$PUBKEY|" \
       -e "s|<WORKLOAD_APP_ID_40_HEX>|$APP_ID|" \
       "$ROOT/deploy/workload/docker-compose.yaml"
# app.json: app_id + os_image (GCP fields are filled by the operator)
python3 - "$ROOT/deploy/workload/app.json" "$APP_ID" "$OS_IMAGE" <<'PY'
import json,sys
f,app_id,osimg=sys.argv[1:4]
d=json.load(open(f)); d["app_id"]=app_id; d["os_image"]=osimg
json.dump(d,open(f,"w"),indent=2)
PY

# ── 9. compute the launcher compose_hash (sha256 of app-compose.json) ──────────
c_step "compute launcher compose_hash"
"$DC" -C "$ROOT/deploy/workload" prepare >/dev/null
LAUNCHER_COMPOSE_HASH="$(sha256sum "$ROOT/deploy/workload/shared/app-compose.json" | cut -d' ' -f1)"
c_ok "launcher_compose_hash=$LAUNCHER_COMPOSE_HASH"

# ── 10. register the launcher compose_hash (G6) ────────────────────────────────
c_step "register launcher compose_hash"
curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"hash\":\"$LAUNCHER_COMPOSE_HASH\"}" \
    "$A/api/v1/admin/launcher-compose-hashes" >/dev/null
c_ok "registered"

# ── 11. register the workload digest under the app (G7) ────────────────────────
c_step "register workload digest under app $APP_ID"
curl -s -X POST "${AUTH[@]}" -H 'content-type: application/json' \
    -d "{\"image\":\"$AR/$WORKLOAD_NAME\",\"digest\":\"sha256:$WL_DIGEST\",\"kid\":\"$IMAGE_KID\"}" \
    "$A/api/v1/admin/tenants/$USER_ID/apps/$APP_ID/workloads" >/dev/null
c_ok "registered $AR/$WORKLOAD_NAME@sha256:$WL_DIGEST (kid=$IMAGE_KID)"

# ── 12. release manifest (consumed by operator-deploy.sh) ──────────────────────
cat > "$ROOT/deploy/.release-manifest.env" <<EOF
# generated by vendor-release.sh — do not edit by hand
APP_ID=$APP_ID
LAUNCHER_COMPOSE_HASH=$LAUNCHER_COMPOSE_HASH
WORKLOAD_IMAGE_DIGEST=sha256:$WL_DIGEST
LITE_LAUNCHER_DIGEST=$LITE_LAUNCHER_DIGEST
AUTHORITY_PUBKEY=$PUBKEY
WORKLOAD_IMAGE=$AR/$WORKLOAD_NAME
EOF
c_ok "wrote deploy/.release-manifest.env"

cat <<EOF

Release ready. Deliver to the operator:
  - the 2 images in $PUBREG (lite-launcher, $WORKLOAD_NAME)
  - the filled template:  deploy/workload/  (compose pins + app.json)
  - deploy/.release-manifest.env  (app_id, digests, AUTHORITY_PUBKEY)
  - tenant api key:  ${API_KEY:-<reuse the one issued at tenant creation>}
Operator then runs:  ./operator-deploy.sh all
EOF
