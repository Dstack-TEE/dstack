#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  aws-ec2-attach-promotion-evidence.sh \
    --manifest PATH \
    --promotion-record PATH \
    --live-smoke-record PATH \
    --output PATH \
    [--aws-account ACCOUNT]

Validates an EC2 AMI promotion record and live-smoke evidence against an
existing dstack AWS EC2 release manifest, then writes a manifest with populated
AWS AMI fields plus embedded promotion and smoke records.

This script does not call AWS APIs.
USAGE
}

manifest=
promotion_record=
live_smoke_record=
output=
aws_account=

require_value() {
  if [ "$#" -lt 2 ]; then
    echo "ERROR: $1 requires a value" >&2
    usage
    exit 2
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --manifest)
      require_value "$@"
      manifest=$2
      shift 2
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
    --output)
      require_value "$@"
      output=$2
      shift 2
      ;;
    --aws-account)
      require_value "$@"
      aws_account=$2
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

if [ -z "$manifest" ] || [ -z "$promotion_record" ] || [ -z "$live_smoke_record" ] || [ -z "$output" ]; then
  usage
  exit 2
fi

for required in jq mktemp; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $required" >&2
    exit 2
  fi
done

for path in "$manifest" "$promotion_record" "$live_smoke_record"; do
  if [ ! -f "$path" ]; then
    echo "ERROR: file not found: $path" >&2
    exit 2
  fi
  jq empty "$path"
done

if ! jq -e '.schema == "dstack-aws-ec2-release-manifest/v1"' "$manifest" >/dev/null; then
  echo "ERROR: manifest schema is not dstack-aws-ec2-release-manifest/v1" >&2
  exit 1
fi

if ! jq -e '.schema == "dstack-aws-ec2-ami-promotion/v1"' "$promotion_record" >/dev/null; then
  echo "ERROR: promotion record schema is not dstack-aws-ec2-ami-promotion/v1" >&2
  exit 1
fi

if ! jq -e '.schema == "dstack-aws-ec2-live-smoke/v1"' "$live_smoke_record" >/dev/null; then
  echo "ERROR: live smoke record schema is not dstack-aws-ec2-live-smoke/v1" >&2
  exit 1
fi

promotion_disk_sha=$(jq -r '.disk.sha256 // empty' "$promotion_record")
promotion_region=$(jq -r '.region // empty' "$promotion_record")
promotion_ami=$(jq -r '.ami.image_id // empty' "$promotion_record")
promotion_ami_name=$(jq -r '.ami.name // empty' "$promotion_record")
promotion_root_snapshot=$(jq -r '.ami.root_snapshot // empty' "$promotion_record")
promotion_tpm_support=$(jq -r '.ami.tpm_support // empty' "$promotion_record")
promotion_boot_mode=$(jq -r '.ami.boot_mode // empty' "$promotion_record")

smoke_region=$(jq -r '.region // empty' "$live_smoke_record")
smoke_ami=$(jq -r '.ami_id // empty' "$live_smoke_record")
smoke_status=$(jq -r '.status // empty' "$live_smoke_record")

for field_name in promotion_disk_sha promotion_region promotion_ami promotion_ami_name promotion_root_snapshot; do
  field_value=${!field_name}
  if [ -z "$field_value" ]; then
    echo "ERROR: promotion record missing $field_name" >&2
    exit 1
  fi
done

if [ "$promotion_boot_mode" != uefi ]; then
  echo "ERROR: promoted AMI boot mode is not uefi: $promotion_boot_mode" >&2
  exit 1
fi

if [ "$promotion_tpm_support" != v2.0 ]; then
  echo "ERROR: promoted AMI TPM support is not v2.0: $promotion_tpm_support" >&2
  exit 1
fi

if [ "$smoke_status" != passed ]; then
  echo "ERROR: live smoke status is not passed: $smoke_status" >&2
  exit 1
fi

if [ "$smoke_ami" != "$promotion_ami" ]; then
  echo "ERROR: live smoke AMI $smoke_ami does not match promoted AMI $promotion_ami" >&2
  exit 1
fi

if [ "$smoke_region" != "$promotion_region" ]; then
  echo "ERROR: live smoke region $smoke_region does not match promotion region $promotion_region" >&2
  exit 1
fi

if ! jq -e --arg disk_sha "$promotion_disk_sha" '
  [.artifacts[]
   | select((.path | endswith("/disk.raw")) or (.path == "disk.raw"))
   | .sha256] | index($disk_sha) != null
' "$manifest" >/dev/null; then
  echo "ERROR: promotion disk SHA256 does not match any disk.raw artifact in manifest: $promotion_disk_sha" >&2
  exit 1
fi

if [ -z "$aws_account" ]; then
  aws_account=$(jq -r '.aws.account // empty' "$manifest")
fi

if [ -z "$aws_account" ]; then
  echo "ERROR: --aws-account is required when manifest .aws.account is empty" >&2
  exit 2
fi

tmp=$(mktemp)
cleanup() {
  rm -f "$tmp"
}
trap cleanup EXIT

jq \
  --arg region "$promotion_region" \
  --arg account "$aws_account" \
  --arg ami_id "$promotion_ami" \
  --arg ami_name "$promotion_ami_name" \
  --arg root_snapshot "$promotion_root_snapshot" \
  --slurpfile promotion "$promotion_record" \
  --slurpfile smoke "$live_smoke_record" '
    .aws.region = $region
    | .aws.account = $account
    | .aws.ami_id = $ami_id
    | .aws.ami_name = $ami_name
    | .aws.root_snapshot = $root_snapshot
    | .promotion_record = $promotion[0]
    | .live_smoke_record = $smoke[0]
  ' "$manifest" >"$tmp"

jq empty "$tmp"
mkdir -p "$(dirname "$output")"
mv "$tmp" "$output"
trap - EXIT

echo "wrote $output"
