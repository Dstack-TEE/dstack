#!/usr/bin/env bash
# setup-swp.sh — domain-whitelist egress for the dstack CVMs via Google
# Secure Web Proxy (SWP). Idempotent; safe to re-run. Runs in staged phases so
# the destructive lockdown only happens after the proxy is verified working.
#
# topology (in-place on the shared `default` VPC, scoped to the dstack CVMs by
# the network tag `dstack-cvm` so other workloads are untouched):
#   - Google APIs (Artifact Registry, GCS) reach the VMs over Private Google
#     Access (no internet); each CVM pins *.googleapis.com / *.pkg.dev to the
#     private VIP via /etc/hosts (no VPC-wide DNS change).
#   - the only true-internet egress is Intel PCS (api.trustedservices.intel.com),
#     forced through the SWP which allows only that host (url-list + policy).
#   - an egress-deny firewall (tag-scoped) makes the SWP the sole internet path.
set -euo pipefail

PROJECT="${PROJECT:-wuhan-workshop}"
REGION="${REGION:-us-central1}"
ZONE="${ZONE:-us-central1-a}"
NETWORK="${NETWORK:-default}"
SUBNET="${SUBNET:-default}"
SSH_KEY="${SSH_KEY:-/home/kvin/.ssh/id_ed25519}"

# resource names
PROXY_SUBNET="swp-proxy-only"
PROXY_SUBNET_RANGE="192.168.100.0/24"   # outside auto-mode's reserved 10.128.0.0/9
GW_ADDR_IP="10.128.0.53"          # free IP in default subnet (VMs use .40/.41)
URLLIST_NAME="dstack-egress-allow"
POLICY_NAME="dstack-egress-policy"
RULE_NAME="allow-intel-pcs"
GATEWAY_NAME="dstack-egress-swp"
SCOPE="dstack-egress-swp"
NETTAG="dstack-cvm"
# private.googleapis.com VIP (serves AR/GCS/etc for internal-only VMs)
PGA_VIP="199.36.153.10"
PGA_RANGE="199.36.153.8/30"

# Intel PCS needs BOTH: api.* (TCB info / QE identity) and certificates.*
# (the SGX Root CA der fetched during quote collateral verification).
ALLOW_DOMAINS=("api.trustedservices.intel.com" "certificates.trustedservices.intel.com")
KMS_VM="dstack-kms-prod"
LAUNCHER_VM="dstack-launcher-prod"

G() { gcloud --project="$PROJECT" "$@"; }
log() { echo -e "\n\033[1;36m[swp] $*\033[0m"; }
have() { "$@" >/dev/null 2>&1; }

WORKDIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.swp"
mkdir -p "$WORKDIR"

###############################################################################
phase_pga() {
  log "phase 1: enable Private Google Access on subnet $SUBNET"
  if [[ "$(G compute networks subnets describe "$SUBNET" --region="$REGION" --format='value(privateIpGoogleAccess)')" == "True" ]]; then
    echo "  PGA already enabled"
  else
    G compute networks subnets update "$SUBNET" --region="$REGION" --enable-private-ip-google-access
    echo "  PGA enabled"
  fi
}

###############################################################################
phase_proxy_subnet() {
  log "phase 2: regional managed proxy-only subnet ($PROXY_SUBNET_RANGE)"
  if have G compute networks subnets describe "$PROXY_SUBNET" --region="$REGION"; then
    echo "  proxy-only subnet exists"
  else
    G compute networks subnets create "$PROXY_SUBNET" \
      --purpose=REGIONAL_MANAGED_PROXY --role=ACTIVE \
      --region="$REGION" --network="$NETWORK" --range="$PROXY_SUBNET_RANGE"
  fi
}

###############################################################################
phase_policy() {
  log "phase 4: url-list + gateway security policy + allow rule"

  # url-list (allowed egress hostnames)
  cat >"$WORKDIR/urllist.yaml" <<EOF
name: projects/$PROJECT/locations/$REGION/urlLists/$URLLIST_NAME
values:
$(printf '  - %s\n' "${ALLOW_DOMAINS[@]}")
EOF
  G network-security url-lists import "$URLLIST_NAME" \
    --location="$REGION" --source="$WORKDIR/urllist.yaml"

  # gateway security policy
  cat >"$WORKDIR/policy.yaml" <<EOF
name: projects/$PROJECT/locations/$REGION/gatewaySecurityPolicies/$POLICY_NAME
description: dstack egress domain whitelist
EOF
  G network-security gateway-security-policies import "$POLICY_NAME" \
    --location="$REGION" --source="$WORKDIR/policy.yaml"

  # allow rule: permit sessions whose SNI host is in the url-list; default-deny
  # is implicit (no matching ALLOW rule => blocked).
  cat >"$WORKDIR/rule.yaml" <<EOF
name: projects/$PROJECT/locations/$REGION/gatewaySecurityPolicies/$POLICY_NAME/rules/$RULE_NAME
description: allow Intel PCS only
enabled: true
priority: 100
basicProfile: ALLOW
sessionMatcher: inUrlList(host(), 'projects/$PROJECT/locations/$REGION/urlLists/$URLLIST_NAME')
tlsInspectionEnabled: false
EOF
  G network-security gateway-security-policies rules import "$RULE_NAME" \
    --location="$REGION" --gateway-security-policy="$POLICY_NAME" \
    --source="$WORKDIR/rule.yaml"
  echo "  policy + rule applied"
}

###############################################################################
phase_gateway() {
  log "phase 3: SECURE_WEB_GATEWAY — PLAINTEXT endpoint (provisioning ~10 min)"
  # No certificateUrls and port 80 => a plaintext HTTP forward-proxy endpoint.
  # This is deliberate: the KMS/dcap-qvl client is reqwest+rustls+webpki-roots,
  # which can't trust a self-signed HTTPS-proxy cert. A plaintext endpoint needs
  # no proxy cert; the CONNECT tunnel still carries end-to-end TLS to Intel, and
  # the proxy enforces the whitelist on the SNI/CONNECT host. The client↔proxy
  # hop is plaintext but stays inside the VPC.
  if have G network-services gateways describe "$GATEWAY_NAME" --location="$REGION"; then
    echo "  gateway exists"
    return
  fi
  cat >"$WORKDIR/gateway.yaml" <<EOF
name: projects/$PROJECT/locations/$REGION/gateways/$GATEWAY_NAME
type: SECURE_WEB_GATEWAY
addresses:
  - $GW_ADDR_IP
ports:
  - 80
gatewaySecurityPolicy: projects/$PROJECT/locations/$REGION/gatewaySecurityPolicies/$POLICY_NAME
network: projects/$PROJECT/global/networks/$NETWORK
subnetwork: projects/$PROJECT/regions/$REGION/subnetworks/$SUBNET
scope: $SCOPE
EOF
  G alpha network-services gateways import "$GATEWAY_NAME" \
    --location="$REGION" --source="$WORKDIR/gateway.yaml"
  echo "  gateway endpoint: http://$GW_ADDR_IP:80 (plaintext, no cert)"
}

###############################################################################
ssh_vm() { # ssh_vm <vm> <remote-cmd>
  gcloud compute ssh "root@$1" --project="$PROJECT" --zone="$ZONE" \
    --tunnel-through-iap --ssh-flag="-i $SSH_KEY" --command="$2" 2>&1 \
    | grep -vE "NumPy|tunnel|cloud.google|^WARNING|^$"
}

phase_hosts() {
  log "phase 6: pin Google-API hostnames to the private VIP ($PGA_VIP) on each CVM"
  # so AR/GCS resolve to the PGA VIP (reachable with no internet) instead of
  # public IPs that the egress-deny would block. Per-VM /etc/hosts keeps the
  # blast radius off the shared VPC's DNS.
  local pins="$PGA_VIP us-central1-docker.pkg.dev
$PGA_VIP pkg.dev
$PGA_VIP storage.googleapis.com
$PGA_VIP www.googleapis.com
$PGA_VIP oauth2.googleapis.com
$PGA_VIP iamcredentials.googleapis.com"
  for vm in "$KMS_VM" "$LAUNCHER_VM"; do
    echo "  -> $vm"
    ssh_vm "$vm" "sed -i '/# dstack-pga-begin/,/# dstack-pga-end/d' /etc/hosts; \
printf '# dstack-pga-begin\n%s\n# dstack-pga-end\n' '$pins' >> /etc/hosts; \
echo applied; grep -c dstack-pga-begin /etc/hosts"
  done
}

phase_tag() {
  log "phase 7: tag the dstack CVMs ($NETTAG) so egress rules scope to them only"
  for vm in "$KMS_VM" "$LAUNCHER_VM"; do
    local tags; tags="$(G compute instances describe "$vm" --zone="$ZONE" --format='value(tags.items)')"
    if [[ "$tags" == *"$NETTAG"* ]]; then echo "  $vm already tagged"; else
      G compute instances add-tags "$vm" --zone="$ZONE" --tags="$NETTAG"
      echo "  tagged $vm"
    fi
  done
}

phase_lockdown() {
  log "phase 8: tag-scoped egress firewall (allow internal/PGA/SWP/metadata, deny rest)"
  # allow rules (priority 900) then deny-all (1000). target-tagged => only the
  # dstack CVMs are affected; every other VM in the VPC is untouched.
  mkfw() { # mkfw <name> <action> <rules-or-empty> <dest> [priority]
    local name="$1" action="$2" rules="$3" dest="$4" prio="${5:-900}"
    if have G compute firewall-rules describe "$name"; then echo "  $name exists"; return; fi
    if [[ "$action" == "ALLOW" ]]; then
      G compute firewall-rules create "$name" --network="$NETWORK" --direction=EGRESS \
        --action=ALLOW --rules="$rules" --destination-ranges="$dest" \
        --target-tags="$NETTAG" --priority="$prio"
    else
      G compute firewall-rules create "$name" --network="$NETWORK" --direction=EGRESS \
        --action=DENY --rules=all --destination-ranges="$dest" \
        --target-tags="$NETTAG" --priority="$prio"
    fi
  }
  mkfw dstack-egress-internal ALLOW all              "10.128.0.0/9"        900
  mkfw dstack-egress-pga      ALLOW tcp:443          "$PGA_RANGE"          900
  mkfw dstack-egress-swp      ALLOW tcp:80           "$GW_ADDR_IP/32"      900
  mkfw dstack-egress-metadata ALLOW tcp:80,tcp:443  "169.254.169.254/32"  900
  mkfw dstack-egress-deny     DENY  ""               "0.0.0.0/0"           1000
  echo "  egress lockdown applied (fail-closed for tag $NETTAG)"
}

phase_noextip() {
  log "phase 9: remove launcher external IP (business CVM => no internet)"
  local cfg; cfg="$(G compute instances describe "$LAUNCHER_VM" --zone="$ZONE" \
    --format='value(networkInterfaces[0].accessConfigs[0].name)')"
  if [[ -z "$cfg" ]]; then echo "  no external IP (already internal-only)"; return; fi
  G compute instances delete-access-config "$LAUNCHER_VM" --zone="$ZONE" --access-config-name="$cfg"
  echo "  external IP removed"
}

phase_verify() {
  log "verify: domain whitelist enforcement through the plaintext SWP from $KMS_VM"
  local addr; addr="$GW_ADDR_IP"
  # plaintext proxy => no CA to push, the rustls client can use this as-is
  ssh_vm "$KMS_VM" "
echo '--- ALLOW: Intel PCS (expect 200/4xx from Intel, NOT proxy-blocked) ---'
curl -s -o /dev/null -w 'http=%{http_code}\n' --max-time 20 \
  -x http://$addr:80 \
  https://api.trustedservices.intel.com/sgx/certification/v4/qe/identity || echo 'curl-failed'
echo '--- DENY: google.com (expect connection reset by proxy) ---'
curl -s -o /dev/null -w 'http=%{http_code}\n' --max-time 20 \
  -x http://$addr:80 \
  https://www.google.com || echo 'blocked (curl-failed as expected)'
"
}

###############################################################################
case "${1:-foundation}" in
  foundation) phase_pga; phase_proxy_subnet; phase_policy; phase_gateway ;;
  pga)        phase_pga ;;
  subnet)     phase_proxy_subnet ;;
  policy)     phase_policy ;;
  gateway)    phase_gateway ;;
  hosts)      phase_hosts ;;
  tag)        phase_tag ;;
  lockdown)   phase_lockdown ;;
  noextip)    phase_noextip ;;
  verify)     phase_verify ;;
  lockdown-all) phase_hosts; phase_tag; phase_lockdown; phase_noextip ;;
  *) echo "usage: $0 {foundation|pga|subnet|policy|gateway|hosts|tag|lockdown|noextip|verify|lockdown-all}"; exit 1 ;;
esac
log "done: ${1:-foundation}"
