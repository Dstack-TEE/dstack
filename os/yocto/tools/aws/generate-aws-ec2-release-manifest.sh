#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  generate-aws-ec2-release-manifest.sh \
    --output PATH \
    --repo PATH \
    --uki PATH \
    --artifact PATH [--artifact PATH ...] \
    [--downloads-dir PATH] \
    [--downloads-manifest-output PATH] \
    [--kernel-config PATH --rootfs-manifest PATH [--rootfs-squashfs PATH]] \
    [--compute-aws-pcr] \
    [--promotion-record PATH] \
    [--live-smoke-record PATH] \
    [--ami-id ID --ami-name NAME --region REGION --aws-account ACCOUNT --root-snapshot SNAP]

Generates a machine-readable AWS EC2 dstack-os release manifest for relying
parties. The manifest records source commits and deterministic source archive
hashes, build artifact hashes, optional Yocto download-cache evidence, optional
AWS NitroTPM PCR references, and optional kernel/rootfs hardening audit output.

The script does not build Yocto and does not sign artifacts.
USAGE
}

output=
repo=
uki=
downloads_dir=
downloads_manifest_output=
kernel_config=
rootfs_manifest=
rootfs_squashfs=
compute_aws_pcr=false
promotion_record=
live_smoke_record=
ami_id=
ami_name=
region=
aws_account=
root_snapshot=
artifacts=()

require_value() {
  if [ "$#" -lt 2 ]; then
    echo "ERROR: $1 requires a value" >&2
    usage
    exit 2
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --output)
      require_value "$@"
      output=$2
      shift 2
      ;;
    --repo)
      require_value "$@"
      repo=$2
      shift 2
      ;;
    --uki)
      require_value "$@"
      uki=$2
      shift 2
      ;;
    --artifact)
      require_value "$@"
      artifacts+=("$2")
      shift 2
      ;;
    --downloads-dir)
      require_value "$@"
      downloads_dir=$2
      shift 2
      ;;
    --downloads-manifest-output)
      require_value "$@"
      downloads_manifest_output=$2
      shift 2
      ;;
    --kernel-config)
      require_value "$@"
      kernel_config=$2
      shift 2
      ;;
    --rootfs-manifest)
      require_value "$@"
      rootfs_manifest=$2
      shift 2
      ;;
    --rootfs-squashfs)
      require_value "$@"
      rootfs_squashfs=$2
      shift 2
      ;;
    --compute-aws-pcr)
      compute_aws_pcr=true
      shift
      ;;
    --promotion-record)
      require_value "$@"
      promotion_record=$2
      shift 2
      ;;
    --live-smoke-record)
      require_value "$@"
      live_smoke_record=$2
      shift 2
      ;;
    --ami-id)
      require_value "$@"
      ami_id=$2
      shift 2
      ;;
    --ami-name)
      require_value "$@"
      ami_name=$2
      shift 2
      ;;
    --region)
      require_value "$@"
      region=$2
      shift 2
      ;;
    --aws-account)
      require_value "$@"
      aws_account=$2
      shift 2
      ;;
    --root-snapshot)
      require_value "$@"
      root_snapshot=$2
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [ -z "$output" ] || [ -z "$repo" ] || [ -z "$uki" ]; then
  usage
  exit 2
fi

if [ "${#artifacts[@]}" -eq 0 ]; then
  echo "ERROR: at least one --artifact is required" >&2
  exit 2
fi

for required in jq git sha256sum stat date; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $required" >&2
    exit 2
  fi
done

check_file() {
  if [ ! -f "$1" ]; then
    echo "ERROR: file not found: $1" >&2
    exit 2
  fi
}

check_dir() {
  if [ ! -d "$1" ]; then
    echo "ERROR: directory not found: $1" >&2
    exit 2
  fi
}

check_dir "$repo"
check_file "$uki"
for artifact in "${artifacts[@]}"; do
  check_file "$artifact"
done
if [ -n "$promotion_record" ]; then
  check_file "$promotion_record"
fi
if [ -n "$live_smoke_record" ]; then
  check_file "$live_smoke_record"
fi

git_dirty_json() {
  local repo=$1
  local status
  status=$(git -C "$repo" status --short --untracked-files=no)
  if [ -z "$status" ]; then
    printf 'false'
  else
    printf 'true'
  fi
}

source_json() {
  local name=$1
  local repo=$2
  local commit branch archive_sha dirty
  commit=$(git -C "$repo" rev-parse HEAD)
  branch=$(git -C "$repo" branch --show-current)
  archive_sha=$(
    git -C "$repo" archive --format=tar --prefix="${name}-${commit}/" "$commit" |
      sha256sum |
      awk '{print $1}'
  )
  dirty=$(git_dirty_json "$repo")
  jq -n \
    --arg name "$name" \
    --arg path "$repo" \
    --arg branch "$branch" \
    --arg commit "$commit" \
    --arg archive_sha256 "$archive_sha" \
    --argjson dirty "$dirty" \
    '{
      name: $name,
      path: $path,
      branch: $branch,
      commit: $commit,
      archive: {
        format: "tar",
        prefix: ($name + "-" + $commit + "/"),
        sha256: $archive_sha256
      },
      dirty_tracked_files: $dirty
    }'
}

artifact_json() {
  local path=$1
  local size sha
  size=$(stat -c%s "$path")
  sha=$(sha256sum "$path" | awk '{print $1}')
  jq -n \
    --arg path "$path" \
    --argjson size "$size" \
    --arg sha256 "$sha" \
    '{path: $path, size: $size, sha256: $sha256}'
}

downloads_json() {
  local dir=$1
  local manifest_output=$2
  local count path_list_sha content_manifest_sha

  check_dir "$dir"
  count=$(find "$dir" -type f | wc -l | tr -d ' ')
  path_list_sha=$(
    (cd "$dir" && find . -type f -printf '%P\n' | LC_ALL=C sort) |
      sha256sum |
      awk '{print $1}'
  )

  if [ -n "$manifest_output" ]; then
    mkdir -p "$(dirname "$manifest_output")"
    (
      cd "$dir"
      while IFS= read -r rel; do
        sha256sum "$rel"
      done < <(find . -type f -printf '%P\n' | LC_ALL=C sort)
    ) >"$manifest_output"
    content_manifest_sha=$(sha256sum "$manifest_output" | awk '{print $1}')
    jq -n \
      --arg path "$dir" \
      --argjson file_count "$count" \
      --arg path_list_sha256 "$path_list_sha" \
      --arg content_manifest "$manifest_output" \
      --arg content_manifest_sha256 "$content_manifest_sha" \
      '{
        path: $path,
        file_count: $file_count,
        sorted_path_list_sha256: $path_list_sha256,
        content_manifest: {
          path: $content_manifest,
          sha256: $content_manifest_sha256
        }
      }'
  else
    jq -n \
      --arg path "$dir" \
      --argjson file_count "$count" \
      --arg path_list_sha256 "$path_list_sha" \
      '{
        path: $path,
        file_count: $file_count,
        sorted_path_list_sha256: $path_list_sha256,
        content_manifest: null
      }'
  fi
}

aws_measurements_json() {
  local uki_path=$1
  local uki_abs uki_dir uki_base pcr_json auth_output auth_sha pcr4 pcr7 pcr12 os_image_hash
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: --compute-aws-pcr requires docker" >&2
    exit 2
  fi
  if ! command -v xxd >/dev/null 2>&1; then
    echo "ERROR: --compute-aws-pcr requires xxd to derive os_image_hash" >&2
    exit 2
  fi
  uki_abs=$(realpath "$uki_path")
  uki_dir=$(dirname "$uki_abs")
  uki_base=$(basename "$uki_abs")
  pcr_json=$(
    docker run --rm --platform linux/amd64 \
      -e UKI_BASENAME="$uki_base" \
      -v "$uki_dir":/artifacts:ro \
      amazonlinux:2023 \
      bash -lc 'dnf install -y aws-nitro-tpm-tools >/tmp/dnf.log && nitro-tpm-pcr-compute --image "/artifacts/$UKI_BASENAME"'
  )
  auth_output=$(
    docker run --rm --platform linux/amd64 \
      -e UKI_BASENAME="$uki_base" \
      -v "$uki_dir":/artifacts:ro \
      amazonlinux:2023 \
      bash -lc 'dnf install -y pesign >/tmp/dnf.log && pesign -h -P -i "/artifacts/$UKI_BASENAME"'
  )
  auth_sha=$(printf '%s\n' "$auth_output" | awk 'NF {print $1; exit}')
  pcr4=$(jq -r '.Measurements.PCR4' <<<"$pcr_json")
  pcr7=$(jq -r '.Measurements.PCR7' <<<"$pcr_json")
  pcr12=$(jq -r '.Measurements.PCR12' <<<"$pcr_json")
  if [ "$pcr4" = null ] || [ "$pcr7" = null ] || [ "$pcr12" = null ]; then
    echo "ERROR: nitro-tpm-pcr-compute output missing PCR4, PCR7, or PCR12" >&2
    exit 1
  fi
  os_image_hash=$(
    printf '%s%s%s' "$pcr4" "$pcr7" "$pcr12" |
      xxd -r -p |
      sha256sum |
      awk '{print $1}'
  )
  jq -n \
    --argjson pcr "$pcr_json" \
    --arg authenticode_sha256 "$auth_sha" \
    --arg os_image_hash "$os_image_hash" \
    '{
      nitro_tpm_pcr_compute: $pcr,
      dstack_os_image_hash: $os_image_hash,
      uki_authenticode_sha256: $authenticode_sha256
    }'
}

hardening_json() {
  local args=()
  local audit_script output_text failures warnings
  audit_script="$(dirname "$0")/audit-aws-ec2-image-hardening.sh"
  if [ ! -x "$audit_script" ]; then
    echo "ERROR: hardening audit script not executable: $audit_script" >&2
    exit 2
  fi
  args+=(--kernel-config "$kernel_config" --rootfs-manifest "$rootfs_manifest")
  if [ -n "$rootfs_squashfs" ]; then
    args+=(--rootfs-squashfs "$rootfs_squashfs")
  fi
  output_text=$("$audit_script" "${args[@]}" 2>&1)
  failures=$(printf '%s\n' "$output_text" | awk -F'[ =]' '/^failures=/{print $2}')
  warnings=$(printf '%s\n' "$output_text" | awk -F'[ =]' '/^failures=/{print $4}')
  jq -n \
    --argjson failures "${failures:-0}" \
    --argjson warnings "${warnings:-0}" \
    --arg output "$output_text" \
    '{failures: $failures, warnings: $warnings, output: $output}'
}

json_file() {
  local path=$1
  jq empty "$path"
  jq . "$path"
}

sources=$(
  source_json dstack-monorepo "$repo" | jq -s .
)

artifact_entries=$(
  for artifact in "${artifacts[@]}"; do
    artifact_json "$artifact"
  done | jq -s .
)

downloads='null'
if [ -n "$downloads_dir" ]; then
  downloads=$(downloads_json "$downloads_dir" "$downloads_manifest_output")
fi

aws_measurements='null'
if [ "$compute_aws_pcr" = true ]; then
  aws_measurements=$(aws_measurements_json "$uki")
fi

hardening='null'
if [ -n "$kernel_config" ] || [ -n "$rootfs_manifest" ] || [ -n "$rootfs_squashfs" ]; then
  if [ -z "$kernel_config" ] || [ -z "$rootfs_manifest" ]; then
    echo "ERROR: hardening audit requires --kernel-config and --rootfs-manifest" >&2
    exit 2
  fi
  hardening=$(hardening_json)
fi

promotion='null'
if [ -n "$promotion_record" ]; then
  promotion=$(json_file "$promotion_record")
fi

live_smoke='null'
if [ -n "$live_smoke_record" ]; then
  live_smoke=$(json_file "$live_smoke_record")
fi

mkdir -p "$(dirname "$output")"
jq -n \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg schema "dstack-aws-ec2-release-manifest/v1" \
  --arg ami_id "$ami_id" \
  --arg ami_name "$ami_name" \
  --arg region "$region" \
  --arg aws_account "$aws_account" \
  --arg root_snapshot "$root_snapshot" \
  --argjson sources "$sources" \
  --argjson artifacts "$artifact_entries" \
  --argjson downloads "$downloads" \
  --argjson aws_measurements "$aws_measurements" \
  --argjson hardening "$hardening" \
  --argjson promotion "$promotion" \
  --argjson live_smoke "$live_smoke" \
  '{
    schema: $schema,
    generated_at: $generated_at,
    trust_model: {
      signed_artifacts_required: false,
      relying_party_requirement: "rebuild or independently verify source, artifacts, AWS PCRs, verifier policy, and endpoint attestation"
    },
    aws: {
      region: ($region | if length > 0 then . else null end),
      account: ($aws_account | if length > 0 then . else null end),
      ami_id: ($ami_id | if length > 0 then . else null end),
      ami_name: ($ami_name | if length > 0 then . else null end),
      root_snapshot: ($root_snapshot | if length > 0 then . else null end)
    },
    sources: $sources,
    artifacts: $artifacts,
    yocto_downloads: $downloads,
    aws_measurements: $aws_measurements,
    hardening_audit: $hardening,
    promotion_record: $promotion,
    live_smoke_record: $live_smoke,
    verifier_instructions: {
      attestation_endpoint: "Use dstack-verifier /verify with a non-empty freshness policy.",
      endpoint_identity: "Use dstack-verifier --verify-cert or ra-tls::attestation::verify_der/verify_pem for public TLS endpoints.",
      required_policy_fields: [
        "attestationMode",
        "osImageHash",
        "mrAggregated",
        "mrSystem",
        "appId",
        "composeHash",
        "instanceId",
        "deviceId",
        "keyProviderInfo",
        "freshness_verified",
        "endpoint_identity_verified"
      ]
    }
  }' >"$output"

jq empty "$output"
echo "wrote $output"
