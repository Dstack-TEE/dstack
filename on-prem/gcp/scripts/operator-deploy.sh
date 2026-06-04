#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# OPERATOR · one-command deploy. Orchestrates the validated flow on the customer's
# GCP, driven entirely by config.env. Assumes the vendor-delivered, pin-filled
# templates are at deploy/kms/ and deploy/launcher/.
#
#   ./operator-deploy.sh sync        # sync the 4 images PUBREG→AR + pull the OS image
#   ./operator-deploy.sh kms         # reserve IP + fill config + deploy + provision + verify KMS
#   ./operator-deploy.sh launcher    # reserve IP + fill config + deploy + verify the workload
#   ./operator-deploy.sh all         # sync → kms → launcher
#
# config.env: GCP_PROJECT, GCP_ZONE, AR_LOCATION/AR_PROJECT/AR_REPO, PUBREG,
#   OS_IMAGE, KMS_IP, LAUNCHER_IP, WORKLOAD_NAME, USER_ID, AUTHORITY_URL,
#   [SWP_PROXY], [DSTACK_CLOUD]

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

GCP="$(cd "$HERE/.." && pwd)"
DC="${DSTACK_CLOUD:-dstack-cloud}"
: "${GCP_PROJECT:?}" "${GCP_ZONE:?}" "${KMS_IP:?}" "${LAUNCHER_IP:?}" "${WORKLOAD_NAME:?}"
OS_VERSION="${OS_VERSION:?set OS_VERSION (dotted published name, e.g. dstack-cloud-nvidia-0.6.1)}"
OS_IMAGE="${OS_VERSION//./-}"           # local image dir / app.json name (dots → dashes)
REGION="${GCP_ZONE%-*}"
AR="${AR_LOCATION:-$REGION}-docker.pkg.dev/${AR_PROJECT:-$GCP_PROJECT}/${AR_REPO:-dstack-private}"
BUCKET="gs://${GCP_PROJECT}-dstack"
KMS_INSTANCE="${KMS_VM:-dstack-kms}"   # must match config.env KMS_VM (provision-kms.sh uses it)
LN_INSTANCE=dstack-launcher

# ── helpers ────────────────────────────────────────────────────────────────────
reserve_ip() { # name ip
    gcloud compute addresses create "$1" --project="$GCP_PROJECT" --region="$REGION" \
        --subnet=default --addresses="$2" 2>/dev/null \
        && c_ok "reserved $1=$2" || c_ok "$1 already reserved"
}
fill_appjson() { # dir instance_name private_ip
    python3 - "$GCP/deploy/$1/app.json" "$2" "$3" "$GCP_PROJECT" "$GCP_ZONE" "$BUCKET" "$OS_IMAGE" <<'PY'
import json,sys
f,name,ip,proj,zone,bucket,osimg=sys.argv[1:8]
d=json.load(open(f)); g=d["gcp_config"]
g["project"],g["zone"],g["bucket"],g["private_ip"],g["instance_name"]=proj,zone,bucket,ip,name
d["os_image"]=osimg
json.dump(d,open(f,"w"),indent=2)
PY
}
# dstack-cloud's global config — needed by pull/prepare/deploy. Sets gcp project/zone,
# the image search path (else `pull` errors "No image_search_paths configured"), and
# kms_urls (so the workload guest-agent reaches our KMS). Call before any stage.
bootstrap_dstack() {
    local f="$HOME/.config/dstack-cloud/config.json"
    mkdir -p "$(dirname "$f")"; [[ -f "$f" ]] || echo '{}' >"$f"
    python3 - "$f" "$KMS_IP" "$GCP_PROJECT" "$GCP_ZONE" <<'PY'
import json,sys
f,ip,proj,zone=sys.argv[1:5]
try: d=json.load(open(f))
except Exception: d={}
d.setdefault("gcp",{}); d.setdefault("services",{})
d["gcp"]["project"],d["gcp"]["zone"]=proj,zone
d["services"]["kms_urls"]=[f"https://{ip}:8000"]
d.setdefault("image_search_paths",["~/.dstack/images"])
json.dump(d,open(f,"w"),indent=2)
PY
    c_ok "dstack-cloud config: project=$GCP_PROJECT  image_search_paths=~/.dstack/images  kms_urls=https://$KMS_IP:8000"
}
tunnel() { # instance remote_port local_port  → echoes PID
    gcloud compute start-iap-tunnel "$1" "$2" --local-host-port="localhost:$3" \
        --project="$GCP_PROJECT" --zone="$GCP_ZONE" >/dev/null 2>&1 &
    echo $!
}

# ── stages ─────────────────────────────────────────────────────────────────────
do_sync() {
    : "${PUBREG:?set PUBREG}"
    for img in dstack-kms key-broker launcher "$WORKLOAD_NAME"; do
        c_step "sync $img → AR"
        "$HERE/sync-image.sh" "$PUBREG/$img:latest" "$img:latest" | tail -1
    done
    c_step "pull OS image $OS_VERSION"
    [[ -f "$HOME/.dstack/images/$OS_IMAGE/disk.raw" ]] && c_ok "already pulled" || "$DC" pull "$OS_VERSION"
}

do_kms() {
    [[ -d "$GCP/deploy/kms" ]] || c_die "deploy/kms missing (vendor-delivered templates?)"
    c_step "prep KMS (reserve IP, fill app.json + user_config, set kms_urls)"
    reserve_ip dstack-kms-ip "$KMS_IP"
    fill_appjson kms "$KMS_INSTANCE" "$KMS_IP"
    printf '{ "DSTACK_REGISTRY": "%s"%s }\n' "$AR" \
        "${SWP_PROXY:+, \"SWP_PROXY\": \"$SWP_PROXY\"}" > "$GCP/deploy/kms/.user-config"

    c_step "deploy KMS CVM"
    "$DC" -C "$GCP/deploy/kms" prepare
    "$DC" -C "$GCP/deploy/kms" deploy
    "$DC" -C "$GCP/deploy/kms" fw allow 8001 8002 || true

    c_step "provision KMS (courier)"
    "$HERE/provision-kms.sh"

    c_step "verify KMS serving + cert SAN"
    local pid; pid="$(tunnel "$KMS_INSTANCE" 8000 18000)"; sleep 8
    curl -sk --max-time 6 https://localhost:18000/prpc/KMS.GetMeta | head -c 40 && echo " …ok" || c_warn "GetMeta failed"
    echo | openssl s_client -connect localhost:18000 2>/dev/null \
        | openssl x509 -noout -ext subjectAltName 2>/dev/null | sed 's/^/  /'
    kill "$pid" 2>/dev/null || true
}

do_launcher() {
    [[ -d "$GCP/deploy/launcher" ]] || c_die "deploy/launcher missing (vendor-delivered templates?)"
    c_step "prep launcher (reserve IP, fill app.json + user_config)"
    reserve_ip dstack-launcher-ip "$LAUNCHER_IP"
    fill_appjson launcher "$LN_INSTANCE" "$LAUNCHER_IP"
    printf '{ "DSTACK_REGISTRY": "%s", "KMS_HOST": "%s" }\n' "$AR" "$KMS_IP" \
        > "$GCP/deploy/launcher/.user-config"

    c_step "deploy launcher CVM"
    "$DC" -C "$GCP/deploy/launcher" prepare
    "$DC" -C "$GCP/deploy/launcher" deploy

    c_step "verify E2E (give it ~2.5min to fetch keys + decrypt + run)"
    sleep 150
    local pid; pid="$(tunnel "$LN_INSTANCE" 9100 19100)"; sleep 8
    curl -s --max-time 6 http://localhost:19100/status | python3 -m json.tool || c_warn "/status not ready yet — check guest-agent :8090 logs"
    kill "$pid" 2>/dev/null || true
}

bootstrap_dstack   # ensure dstack-cloud's global config exists before any stage

case "${1:-}" in
    sync)     do_sync ;;
    kms)      do_kms ;;
    launcher) do_launcher ;;
    all)      do_sync; do_kms; do_launcher ;;
    *) echo "usage: $0 {sync|kms|launcher|all}"; exit 1 ;;
esac
