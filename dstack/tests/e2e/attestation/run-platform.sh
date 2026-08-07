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
GCP_TPM_REPLAY=null
AWS_PCR_REPLAY=null
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
  GCP_TPM_REPLAY=$(jq -cn \
    --arg event_log "$(base64 -w0 /usr/local/share/dstack/tpm_eventlog.bin)" \
    '{event_log:$event_log}')
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
  AWS_PCR_REPLAY=$(jq -cn --arg pcr "$ZERO_PCR" \
    '{version:1,events:[],pcr4:$pcr,pcr7:$pcr,pcr12:$pcr}')
  VM_CONFIG=$(jq -cn \
    --arg os "$OS_IMAGE_HASH" \
    --arg checksum "$(base64 -w0 "$WORK/sha256sum.txt")" \
    --arg measurement "$(base64 -w0 "$WORK/measurement.aws.cbor")" \
    --argjson replay "$AWS_PCR_REPLAY" \
    '{os_image_hash:$os,aws_measurement:{checksum_file:$checksum,measurement:$measurement},aws_pcr_replay:$replay}')
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

cat > "$SIM_CONFIG" <<JSON
{
  "platform": "$TEE_PLATFORM",
  "mock_attestation_seed": "$SEED",
  "collateral_base_url": "http://127.0.0.1:18088",
  "mr_config": $(jq -Rn --arg value "$MR_CONFIG" '$value'),
  "vm_config": $(jq -Rn --arg value "$VM_CONFIG" '$value'),
  "gcp_tpm_replay": $GCP_TPM_REPLAY,
  "aws_pcr_replay": $AWS_PCR_REPLAY
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
cp "$WORK/request.json.verification.json" "$WORK/development-root-verification.json"
echo '{"development_root_accepted":true}'

# The same simulator evidence must fail against the verifier's built-in
# production roots. Keep the mock collateral endpoints so this assertion tests
# the trust-anchor boundary rather than network or collateral availability.
cat > "$WORK/production-verifier.toml" <<EOF_CONFIG
address = "127.0.0.1"
port = 8080
image_cache_dir = "$WORK/production-image-cache"
image_download_url = "http://127.0.0.1:9/mr_{OS_IMAGE_HASH}.tar.gz"
image_download_timeout_secs = 1

[attestation.urls]
pccs = "http://127.0.0.1:18088"
amd_kds = "http://127.0.0.1:18088/vcek/v1"
EOF_CONFIG
rm -f "$WORK/request.json.verification.json"
set +e
dstack-verifier --config "$WORK/production-verifier.toml" --verify "$WORK/request.json" \
  >"$WORK/production-verifier.log" 2>&1
PRODUCTION_VERIFIER_RC=$?
set -e
if [[ ! -s "$WORK/request.json.verification.json" ]]; then
  cat "$WORK/production-verifier.log" >&2
  echo "production-root verifier did not emit a verification result" >&2
  exit 1
fi
cat "$WORK/request.json.verification.json"
if (( PRODUCTION_VERIFIER_RC == 0 )) || ! jq -e '.is_valid == false' "$WORK/request.json.verification.json" >/dev/null; then
  cat "$WORK/production-verifier.log" >&2
  echo "simulator evidence unexpectedly passed production-root verification" >&2
  exit 1
fi
echo '{"production_root_rejected":true}'
echo "[$TEE_PLATFORM${TDX_ATTESTATION_VARIANT:+/$TDX_ATTESTATION_VARIANT}] dstack-util -> verifier trust-root isolation E2E passed"
