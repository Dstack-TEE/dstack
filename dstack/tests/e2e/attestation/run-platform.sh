#!/bin/bash

# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

: "${TEE_PLATFORM:?TEE_PLATFORM is required}"
SEED=7171717171717171717171717171717171717171717171717171717171717171
REPORT_DATA=42424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242424242
WORK=/run/attestation-e2e
SYS_CONFIG=/dstack/.host-shared/.sys-config.json
SIM_CONFIG=/dstack/.host-shared/.tee-simulator.json
mkdir -p "$WORK" /run/log/dstack
mount -t tmpfs -o mode=0755 tmpfs /sys/kernel/config
mkdir -p /sys/kernel/config/tsm/report

VM_CONFIG='{}'
MR_CONFIG='{"version":3,"app_id":"","compose_hash":"","key_provider":"none"}'
if [[ "$TEE_PLATFORM" == dstack-tdx ]]; then
  VM_CONFIG=$(jq -c --arg variant "${TDX_ATTESTATION_VARIANT:?}" \
    '.vm_config | fromjson | .tdx_attestation_variant = $variant' \
    /usr/local/share/dstack/tdx-lite-getquote.json)
elif [[ "$TEE_PLATFORM" == dstack-gcp-tdx ]]; then
  UKI_HASH=9ab14a46f858662a89adc102d2a57a13f52f75c1769d65a4c34edbbfc8855f0f
  printf '%s\n' "$UKI_HASH" > "$WORK/gcp-uki-hash"
  dstack-mr gcp-measurement-cbor "$WORK/gcp-uki-hash" > "$WORK/measurement.gcp.cbor"
  MEASUREMENT_HASH=$(sha256sum "$WORK/measurement.gcp.cbor" | cut -d' ' -f1)
  printf '%s  measurement.gcp.cbor\n' "$MEASUREMENT_HASH" > "$WORK/sha256sum.txt"
  OS_IMAGE_HASH=$(sha256sum "$WORK/sha256sum.txt" | cut -d' ' -f1)
  VM_CONFIG=$(jq -cn \
    --arg os "$OS_IMAGE_HASH" \
    --arg checksum "$(base64 -w0 "$WORK/sha256sum.txt")" \
    --arg measurement "$(base64 -w0 "$WORK/measurement.gcp.cbor")" \
    '{os_image_hash:$os,gcp_measurement:{checksum_file:$checksum,measurement:$measurement}}')
elif [[ "$TEE_PLATFORM" == dstack-amd-sev-snp ]]; then
  jq -r .attestation /usr/local/share/dstack/sev-snp-attestation.json | xxd -r -p > "$WORK/snp-fixture.bin"
  dstack-util attest-json --input "$WORK/snp-fixture.bin" --output "$WORK/snp-fixture.json"
  VM_CONFIG=$(jq -c '.config | fromjson' "$WORK/snp-fixture.json")
  MR_CONFIG=$(jq -r .mr_config <<<"$VM_CONFIG")
elif [[ "$TEE_PLATFORM" == dstack-nitro-enclave ]]; then
  for index in 0 1 2; do
    printf 'dstack-tee-simulator/nsm/pcr/%s' "$index" |
      sha384sum | cut -d' ' -f1 > "$WORK/pcr$index"
  done
  OS_IMAGE_HASH=$(
    cat "$WORK/pcr0" "$WORK/pcr1" "$WORK/pcr2" |
      xxd -r -p | sha256sum | cut -d' ' -f1
  )
  VM_CONFIG=$(jq -cn --arg os "$OS_IMAGE_HASH" '{os_image_hash:$os}')
elif [[ "$TEE_PLATFORM" == dstack-aws-nitro-tpm ]]; then
  ZERO_PCR=$(printf '00%.0s' $(seq 1 48))
  printf '%s' "$ZERO_PCR" > "$WORK/pcr4"
  cp "$WORK/pcr4" "$WORK/pcr7"
  cp "$WORK/pcr4" "$WORK/pcr12"
  dstack-mr aws-measurement-cbor "$ZERO_PCR" "$ZERO_PCR" "$ZERO_PCR" \
    > "$WORK/measurement.aws.cbor"
  MEASUREMENT_HASH=$(sha256sum "$WORK/measurement.aws.cbor" | cut -d' ' -f1)
  printf '%s  measurement.aws.cbor\n' "$MEASUREMENT_HASH" > "$WORK/sha256sum.txt"
  OS_IMAGE_HASH=$(sha256sum "$WORK/sha256sum.txt" | cut -d' ' -f1)
  VM_CONFIG=$(jq -cn \
    --arg os "$OS_IMAGE_HASH" \
    --arg checksum "$(base64 -w0 "$WORK/sha256sum.txt")" \
    --arg measurement "$(base64 -w0 "$WORK/measurement.aws.cbor")" \
    '{os_image_hash:$os,aws_measurement:{checksum_file:$checksum,measurement:$measurement}}')
fi

cleanup() {
  set +e
  [[ -n "${SIM_PID:-}" ]] && kill "$SIM_PID" 2>/dev/null
  [[ -n "${COLLATERAL_PID:-}" ]] && kill "$COLLATERAL_PID" 2>/dev/null
  [[ -s /run/dstack/swtpm.pid ]] && kill "$(cat /run/dstack/swtpm.pid)" 2>/dev/null
  fusermount3 -uz /sys/kernel/config/tsm/report 2>/dev/null
  umount /sys/class/dmi/id/sys_vendor 2>/dev/null
  umount /sys/class/dmi/id/product_name 2>/dev/null
}
trap cleanup EXIT

cat > "$SYS_CONFIG" <<JSON
{
  "kms_urls": [],
  "gateway_urls": [],
  "collateral_urls": {
    "pccs": "http://127.0.0.1:18088",
    "amd_kds": "http://127.0.0.1:18088/vcek/v1"
  },
  "docker_registry": null,
  "host_api_url": null,
  "mr_config": $(jq -Rn --arg value "$MR_CONFIG" '$value'),
  "vm_config": $(jq -Rn --arg value "$VM_CONFIG" '$value')
}
JSON

SIM_COLLATERAL_URL=http://127.0.0.1:18088
if [[ "$TEE_PLATFORM" == dstack-gcp-tdx ]]; then
  # The GCP vTPM owns a collateral listener because its generated AK/EK
  # certificates carry AIA URLs. Keep it distinct from the shared collateral
  # fixture used to prepare the other platform roots.
  SIM_COLLATERAL_URL=http://127.0.0.1:18089
fi
cat > "$SIM_CONFIG" <<JSON
{
  "platform": "$TEE_PLATFORM",
  "mock_attestation_seed": "$SEED",
  "collateral_base_url": "$SIM_COLLATERAL_URL",
  "mr_config": $(jq -Rn --arg value "$MR_CONFIG" '$value'),
  "vm_config": $(jq -Rn --arg value "$VM_CONFIG" '$value')
}
JSON

# Reconstruct public roots and production-shaped collateral from the same seed.
dstack-mock-attestation serve \
  --listen 127.0.0.1:18088 \
  --config "$SIM_CONFIG" \
  --output "$WORK/roots" >"$WORK/collateral.log" 2>&1 &
COLLATERAL_PID=$!
for _ in $(seq 1 100); do
  curl -fsS http://127.0.0.1:18088/tpm/aia/root.pem >/dev/null 2>&1 && break
  sleep .05
done
curl -fsS http://127.0.0.1:18088/tpm/aia/root.pem >/dev/null

if [[ "$TEE_PLATFORM" == dstack-gcp-tdx || "$TEE_PLATFORM" == dstack-aws-nitro-tpm ]]; then
  mount -t tmpfs -o mode=0755 tmpfs /sys/kernel/security
  mkdir -p /sys/kernel/security/tpm0
  cp /usr/local/share/dstack/tpm_eventlog.bin /sys/kernel/security/tpm0/binary_bios_measurements
  modprobe tpm_vtpm_proxy
  if [[ ! -e /dev/vtpmx && -r /sys/class/misc/vtpmx/dev ]]; then
    IFS=: read -r major minor < /sys/class/misc/vtpmx/dev
    mknod /dev/vtpmx c "$major" "$minor"
  fi
  chmod 0666 /dev/vtpmx
fi

dstack-tee-simulator --config "$SIM_CONFIG" >"$WORK/simulator.log" 2>&1 &
SIM_PID=$!
case "$TEE_PLATFORM" in
  dstack-tdx|dstack-gcp-tdx|dstack-amd-sev-snp)
    for _ in $(seq 1 200); do
      [[ -e /sys/kernel/config/tsm/report/provider || -e /sys/kernel/config/tsm/report/com.intel.dcap/outblob ]] && break
      sleep .05
    done
    ;;
  dstack-nitro-enclave)
    for _ in $(seq 1 200); do
      if [[ ! -e /dev/nsm && -r /sys/class/cuse/nsm/dev ]]; then
        IFS=: read -r major minor < /sys/class/cuse/nsm/dev
        mknod /dev/nsm c "$major" "$minor"
      fi
      [[ -e /dev/nsm ]] && break
      sleep .05
    done
    if [[ ! -e /dev/nsm ]]; then
      echo "NSM device node was not created" >&2
      find /sys -path '*nsm*' -o -path '*cuse*' 2>/dev/null | head -100 >&2
      cat "$WORK/simulator.log" >&2
      exit 1
    fi
    ;;
  dstack-aws-nitro-tpm)
    for _ in $(seq 1 200); do
      [[ -e /dev/tpm0 || -e /dev/tpmrm0 ]] && break
      sleep .05
    done
    if [[ ! -e /dev/tpm0 && ! -e /dev/tpmrm0 ]]; then
      echo "NitroTPM device node was not created" >&2
      cat "$WORK/simulator.log" >&2
      exit 1
    fi
    ;;
esac
if ! kill -0 "$SIM_PID" 2>/dev/null; then
  echo "[$TEE_PLATFORM] simulator failed:" >&2
  cat "$WORK/simulator.log" >&2
  exit 1
fi
echo "platform=$TEE_PLATFORM dmi_vendor=$(cat /sys/class/dmi/id/sys_vendor 2>/dev/null || true) dmi_product=$(cat /sys/class/dmi/id/product_name 2>/dev/null || true) nsm=$(test -e /dev/nsm && echo yes || echo no)"

export DCAP_TDX_RTMR_SYSFS_PATH=/sys/kernel/config/tsm/report/com.intel.dcap/measurements
export DSTACK_CCEL_FILE=/sys/kernel/config/tsm/report/com.intel.dcap/ccel
if ! ATTESTATION_HEX=$(dstack-util attest --report-data "$REPORT_DATA" --hex); then
  cat "$WORK/simulator.log" >&2
  exit 1
fi
jq -n --arg attestation "$ATTESTATION_HEX" \
  '{attestation: $attestation, debug: true}' > "$WORK/request.json"

cat > "$WORK/verifier.toml" <<EOF_CONFIG
address = "127.0.0.1"
port = 8080
image_cache_dir = "$WORK/image-cache"
image_download_url = "http://127.0.0.1:9/mr_{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 1

[attestation]
insecure_allow_external_trust_anchors = true

[attestation.urls]
pccs = "http://127.0.0.1:18088"
amd_kds = "http://127.0.0.1:18088/vcek/v1"

[attestation.root_ca]
tdx = "$WORK/roots/tdx-root-ca.pem"
gcp_tpm = "$WORK/roots/tpm-root-ca.pem"
aws_nitro_enclave = "$WORK/roots/nsm-root-ca.pem"
aws_nitro_tpm = "$WORK/roots/nsm-root-ca.pem"
sev_snp_milan = "$WORK/roots/sev-snp-root-ca.pem"
sev_snp_genoa = "$WORK/roots/sev-snp-root-ca.pem"
sev_snp_turin = "$WORK/roots/sev-snp-root-ca.pem"
EOF_CONFIG

set +e
dstack-verifier --config "$WORK/verifier.toml" --verify "$WORK/request.json" \
  >"$WORK/verifier.log" 2>&1
VERIFIER_RC=$?
set -e
if [[ ! -s "$WORK/request.json.verification.json" ]]; then
  cat "$WORK/verifier.log" >&2
  exit 1
fi
if (( VERIFIER_RC != 0 )); then
  cat "$WORK/verifier.log" >&2
  exit "$VERIFIER_RC"
fi
cat "$WORK/request.json.verification.json"
jq -e '.details.quote_verified == true' "$WORK/request.json.verification.json" >/dev/null
jq -e '.is_valid == true' "$WORK/request.json.verification.json" >/dev/null
jq -e '.details.os_image_hash_verified == true' "$WORK/request.json.verification.json" >/dev/null
jq -e '.details.event_log_verified == true' "$WORK/request.json.verification.json" >/dev/null
jq -e '.details.simulated == true' "$WORK/request.json.verification.json" >/dev/null

# Flip one authenticated byte while preserving the versioned envelope and JSON
# shape. Every platform must reject the mutation and must not leave an accepted
# verification decision behind.
ORIGINAL_ATTESTATION=$(jq -r .attestation "$WORK/request.json")
PREFIX=${ORIGINAL_ATTESTATION:0:2}
if [[ "$PREFIX" == "00" ]]; then
  MUTATED_PREFIX=01
else
  MUTATED_PREFIX=00
fi
jq --arg attestation "${MUTATED_PREFIX}${ORIGINAL_ATTESTATION:2}" \
  '.attestation = $attestation' "$WORK/request.json" > "$WORK/mutated-request.json"
set +e
dstack-verifier --config "$WORK/verifier.toml" --verify "$WORK/mutated-request.json" \
  >"$WORK/mutation-policy.log" 2>&1
MUTATION_RC=$?
set -e
if (( MUTATION_RC == 0 )); then
  echo "tampered $TEE_PLATFORM evidence was accepted" >&2
  cat "$WORK/mutation-policy.log" >&2
  exit 1
fi
if [[ -s "$WORK/mutated-request.json.verification.json" ]] &&
   jq -e '.is_valid == true' "$WORK/mutated-request.json.verification.json" >/dev/null 2>&1; then
  echo "tampered $TEE_PLATFORM evidence left an accepted decision" >&2
  cat "$WORK/mutated-request.json.verification.json" >&2
  exit 1
fi

# Keeping the development roots while removing the explicit opt-in models
# production policy. It must fail before a verification decision is created.
grep -v '^insecure_allow_external_trust_anchors = true$' \
  "$WORK/verifier.toml" > "$WORK/production-verifier.toml"
set +e
dstack-verifier --config "$WORK/production-verifier.toml" --verify "$WORK/request.json" \
  >"$WORK/production-policy.log" 2>&1
PRODUCTION_RC=$?
set -e
if (( PRODUCTION_RC == 0 )); then
  echo "production policy accepted development trust roots" >&2
  cat "$WORK/production-policy.log" >&2
  exit 1
fi
if ! grep -qiE 'external trust|insecure_allow_external_trust_anchors|custom root' \
  "$WORK/production-policy.log"; then
  echo "production policy rejection did not identify the development trust-root gate" >&2
  cat "$WORK/production-policy.log" >&2
  exit 1
fi

jq -n \
  --arg platform "$TEE_PLATFORM" \
  --arg variant "${TDX_ATTESTATION_VARIANT:-}" \
  --argjson development "$(cat "$WORK/request.json.verification.json")" \
  --argjson production_rc "$PRODUCTION_RC" \
  '{platform:$platform,variant:$variant,development:$development,production:{accepted:false,returncode:$production_rc}}'
echo "[$TEE_PLATFORM${TDX_ATTESTATION_VARIANT:+/$TDX_ATTESTATION_VARIANT}] development policy labeled simulated evidence and production policy rejected it"
