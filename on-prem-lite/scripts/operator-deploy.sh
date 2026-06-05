#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPERATOR · one-command deploy of the single on-prem-lite workload CVM on GCP.
# Driven by config.env + the vendor-delivered release manifest. No KMS CVM, no
# static-IP/cert-SAN, no SWP — just the launcher CVM and one courier hop.
#
#   ./operator-deploy.sh sync      # sync lite-launcher + workload images PUBREG→AR + pull OS image
#   ./operator-deploy.sh deploy    # reserve IP + fill config + deploy the launcher CVM
#   ./operator-deploy.sh license   # courier: attest + install a License (launcher runs the workload)
#   ./operator-deploy.sh all       # sync → deploy → license
#   ./operator-deploy.sh update    # day-2: re-run license (renew / rolling update)
#
# config.env: GCP_PROJECT, GCP_ZONE, AR_LOCATION/AR_PROJECT/AR_REPO, PUBREG,
#   OS_VERSION, WORKLOAD_IP, WORKLOAD_NAME, USER_ID, AUTHORITY_URL,
#   AUTHORITY_API_KEY, [DSTACK_CLOUD]

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

DC="${DSTACK_CLOUD:-dstack-cloud}"
: "${GCP_PROJECT:?}" "${GCP_ZONE:?}" "${WORKLOAD_IP:?}" "${WORKLOAD_NAME:?}"
OS_VERSION="${OS_VERSION:?set OS_VERSION (dotted published name, e.g. dstack-cloud-nvidia-0.6.1)}"
OS_IMAGE="${OS_VERSION//./-}"           # local image dir / app.json name (dots → dashes)
REGION="${GCP_ZONE%-*}"
AR="${AR_LOCATION:-$REGION}-docker.pkg.dev/${AR_PROJECT:-$GCP_PROJECT}/${AR_REPO:-dstack-private}"
BUCKET="gs://${GCP_PROJECT}-dstack"
WL_INSTANCE=dstack-lite-workload

# vendor-delivered release manifest: app_id + digests for the license stage.
MANIFEST="$ROOT/deploy/.release-manifest.env"
[[ -f "$MANIFEST" ]] || c_die "no release manifest at $MANIFEST (vendor runs ./vendor-release.sh first)"
# shellcheck disable=SC1090
source "$MANIFEST"

# ── helpers ────────────────────────────────────────────────────────────────────
reserve_ip() { # name ip
    gcloud compute addresses create "$1" --project="$GCP_PROJECT" --region="$REGION" \
        --subnet=default --addresses="$2" 2>/dev/null \
        && c_ok "reserved $1=$2" || c_ok "$1 already reserved"
}
fill_appjson() { # dir instance_name private_ip
    python3 - "$ROOT/deploy/$1/app.json" "$2" "$3" "$GCP_PROJECT" "$GCP_ZONE" "$BUCKET" "$OS_IMAGE" <<'PY'
import json,sys
f,name,ip,proj,zone,bucket,osimg=sys.argv[1:8]
d=json.load(open(f)); g=d["gcp_config"]
g["project"],g["zone"],g["bucket"],g["private_ip"],g["instance_name"]=proj,zone,bucket,ip,name
d["os_image"]=osimg
json.dump(d,open(f,"w"),indent=2)
PY
}
# dstack-cloud's global config — needed by pull/prepare/deploy. Sets gcp
# project/zone + the image search path. NO kms_urls: the lite profile has no KMS
# (the disk is vTPM-sealed and the workload gets only an image CEK).
bootstrap_dstack() {
    local f="$HOME/.config/dstack-cloud/config.json"
    mkdir -p "$(dirname "$f")"; [[ -f "$f" ]] || echo '{}' >"$f"
    python3 - "$f" "$GCP_PROJECT" "$GCP_ZONE" <<'PY'
import json,sys
f,proj,zone=sys.argv[1:4]
try: d=json.load(open(f))
except Exception: d={}
d.setdefault("gcp",{})
d["gcp"]["project"],d["gcp"]["zone"]=proj,zone
d.setdefault("image_search_paths",["~/.dstack/images"])
json.dump(d,open(f,"w"),indent=2)
PY
    c_ok "dstack-cloud config: project=$GCP_PROJECT  image_search_paths=~/.dstack/images  (no kms_urls — lite)"
}
tunnel() { # instance remote_port local_port  → echoes PID
    gcloud compute start-iap-tunnel "$1" "$2" --local-host-port="localhost:$3" \
        --project="$GCP_PROJECT" --zone="$GCP_ZONE" >/dev/null 2>&1 &
    echo $!
}

# ── stages ─────────────────────────────────────────────────────────────────────
do_sync() {
    : "${PUBREG:?set PUBREG}"
    for img in lite-launcher "$WORKLOAD_NAME"; do
        c_step "sync $img → AR"
        "$HERE/sync-image.sh" "$PUBREG/$img:latest" "$img:latest" | tail -1
    done
    c_step "pull OS image $OS_VERSION"
    [[ -f "$HOME/.dstack/images/$OS_IMAGE/disk.raw" ]] && c_ok "already pulled" || "$DC" pull "$OS_VERSION"
}

do_deploy() {
    [[ -d "$ROOT/deploy/workload" ]] || c_die "deploy/workload missing (vendor-delivered template?)"
    c_step "prep workload (reserve IP, fill app.json + user_config)"
    reserve_ip dstack-lite-workload-ip "$WORKLOAD_IP"
    fill_appjson workload "$WL_INSTANCE" "$WORKLOAD_IP"
    printf '{ "DSTACK_REGISTRY": "%s" }\n' "$AR" > "$ROOT/deploy/workload/.user-config"

    c_step "deploy workload CVM"
    "$DC" -C "$ROOT/deploy/workload" prepare
    "$DC" -C "$ROOT/deploy/workload" deploy
    "$DC" -C "$ROOT/deploy/workload" fw allow 9000 || true   # courier port over IAP
    c_ok "deployed $WL_INSTANCE — license it next:  $0 license"
}

do_license() {
    : "${AUTHORITY_URL:?set AUTHORITY_URL}" "${USER_ID:?set USER_ID}"
    : "${APP_ID:?missing APP_ID (from release manifest)}"
    : "${WORKLOAD_IMAGE_DIGEST:?missing WORKLOAD_IMAGE_DIGEST (from release manifest)}"

    c_step "opening IAP tunnel localhost:19000 → $WL_INSTANCE:9000"
    local pid; pid="$(tunnel "$WL_INSTANCE" 9000 19000)"
    trap 'kill "$pid" 2>/dev/null || true' RETURN
    # a freshly-deployed CVM needs a few minutes to boot + start the launcher —
    # wait for a non-empty /healthz (up to ~6min) rather than racing.
    c_step "waiting for launcher on the tunnel (CVM may still be booting)"
    local hz=""
    for _ in $(seq 1 90); do
        hz="$(curl -s --max-time 3 http://localhost:19000/healthz 2>/dev/null || true)"
        [ -n "$hz" ] && break
        sleep 4
    done
    [ -n "$hz" ] || c_die "launcher not reachable on :19000 after ~6min (CVM booted? is 'fw allow 9000' applied?)"
    c_ok "launcher healthz: $hz"

    c_step "courier attest (user_id=$USER_ID app_id=$APP_ID)"
    LAUNCHER_URL="http://localhost:19000" \
    AUTHORITY_URL="$AUTHORITY_URL" \
    USER_ID="$USER_ID" \
    APP_ID="$APP_ID" \
    WORKLOAD_DIGEST="$WORKLOAD_IMAGE_DIGEST" \
    AUTHORITY_API_KEY="${AUTHORITY_API_KEY:-}" \
        python3 "$ROOT/cli/license-ctl.py" attest

    c_step "waiting for the workload to come up (decrypt + run takes a moment)"
    local st=""
    for _ in $(seq 1 30); do
        st="$(curl -s --max-time 4 http://localhost:19000/status 2>/dev/null || true)"
        echo "$st" | grep -q '"workload_running": *true' && break
        sleep 6
    done
    if [ -n "$st" ]; then echo "$st" | python3 -m json.tool; else c_warn "/status not ready — check launcher logs"; fi
}

bootstrap_dstack   # ensure dstack-cloud's global config exists before any stage

case "${1:-}" in
    sync)    do_sync ;;
    deploy)  do_deploy ;;
    license) do_license ;;
    all)     do_sync; do_deploy; do_license ;;
    update)  do_license ;;                 # day-2: renew / rolling update (fresh License)
    *) echo "usage: $0 {sync|deploy|license|all|update}"; exit 1 ;;
esac
