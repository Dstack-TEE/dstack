#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  aws-ec2-import-attestable-ami.sh \
    --disk PATH \
    --s3-bucket BUCKET \
    --name AMI_NAME \
    --region REGION \
    [--s3-prefix PREFIX] \
    [--s3-key KEY] \
    [--description TEXT] \
    [--role-name ROLE] \
    [--client-token TOKEN] \
    [--root-device-name DEVICE] \
    [--volume-type TYPE] \
    [--poll-interval SECONDS] \
    [--timeout SECONDS] \
    [--output PATH] \
    [--tag KEY=VALUE]... \
    [--delete-s3-object-after-import]

Uploads a raw dstack AWS EC2 release disk to S3, imports it as an EBS
snapshot, registers an x86_64 HVM AMI with UEFI and NitroTPM v2.0 enabled,
tags the snapshot and AMI, waits until the AMI is available, and writes a JSON
promotion record.

The script assumes the S3 bucket exists and the AWS account has VM Import/Export
permissions, usually through the default vmimport role or --role-name.
USAGE
}

disk=
s3_bucket=
s3_prefix=
s3_key=
name=
region=
description=
role_name=
client_token=
root_device_name=/dev/sda1
volume_type=gp3
poll_interval=30
timeout_seconds=7200
output=
delete_s3_object=false
extra_tags=()

require_value() {
  if [ "$#" -lt 2 ]; then
    echo "ERROR: $1 requires a value" >&2
    usage
    exit 2
  fi
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --disk)
      require_value "$@"
      disk=$2
      shift 2
      ;;
    --s3-bucket)
      require_value "$@"
      s3_bucket=$2
      shift 2
      ;;
    --s3-prefix)
      require_value "$@"
      s3_prefix=$2
      shift 2
      ;;
    --s3-key)
      require_value "$@"
      s3_key=$2
      shift 2
      ;;
    --name)
      require_value "$@"
      name=$2
      shift 2
      ;;
    --region)
      require_value "$@"
      region=$2
      shift 2
      ;;
    --description)
      require_value "$@"
      description=$2
      shift 2
      ;;
    --role-name)
      require_value "$@"
      role_name=$2
      shift 2
      ;;
    --client-token)
      require_value "$@"
      client_token=$2
      shift 2
      ;;
    --root-device-name)
      require_value "$@"
      root_device_name=$2
      shift 2
      ;;
    --volume-type)
      require_value "$@"
      volume_type=$2
      shift 2
      ;;
    --poll-interval)
      require_value "$@"
      poll_interval=$2
      shift 2
      ;;
    --timeout)
      require_value "$@"
      timeout_seconds=$2
      shift 2
      ;;
    --output)
      require_value "$@"
      output=$2
      shift 2
      ;;
    --tag)
      require_value "$@"
      extra_tags+=("$2")
      shift 2
      ;;
    --delete-s3-object-after-import)
      delete_s3_object=true
      shift
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

if [ -z "$disk" ] || [ -z "$s3_bucket" ] || [ -z "$name" ] || [ -z "$region" ]; then
  usage
  exit 2
fi

if [ ! -f "$disk" ]; then
  echo "ERROR: disk not found: $disk" >&2
  exit 2
fi

for required in aws jq sha256sum stat date sed realpath; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $required" >&2
    exit 2
  fi
done

case "$poll_interval" in
  ''|*[!0-9]*)
    echo "ERROR: --poll-interval must be an integer number of seconds" >&2
    exit 2
    ;;
esac

case "$timeout_seconds" in
  ''|*[!0-9]*)
    echo "ERROR: --timeout must be an integer number of seconds" >&2
    exit 2
    ;;
esac

if [ "$poll_interval" -eq 0 ]; then
  echo "ERROR: --poll-interval must be greater than zero" >&2
  exit 2
fi

disk_abs=$(realpath "$disk")
disk_sha256=$(sha256sum "$disk_abs" | awk '{print $1}')
disk_size_bytes=$(stat -c%s "$disk_abs")
generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)

if [ -z "$description" ]; then
  description="dstack AWS EC2 Attestable AMI import for $name"
fi

if [ -z "$client_token" ]; then
  safe_name=$(printf '%s' "$name" | sed 's/[^A-Za-z0-9_-]/-/g' | cut -c1-48)
  client_token="${safe_name}-${disk_sha256:0:32}"
fi

if [ -z "$s3_key" ]; then
  safe_name=$(printf '%s' "$name" | sed 's/[^A-Za-z0-9._-]/-/g')
  s3_prefix=${s3_prefix#/}
  s3_prefix=${s3_prefix%/}
  if [ -n "$s3_prefix" ]; then
    s3_key="$s3_prefix/$safe_name-$disk_sha256.raw"
  else
    s3_key="$safe_name-$disk_sha256.raw"
  fi
fi

echo "Uploading $disk_abs to s3://$s3_bucket/$s3_key" >&2
aws s3 cp "$disk_abs" "s3://$s3_bucket/$s3_key" --region "$region" >/dev/null

tmpdir=$(mktemp -d)
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

disk_container=$(
  jq -cn \
    --arg desc "$description" \
    --arg bucket "$s3_bucket" \
    --arg key "$s3_key" \
    '{Description: $desc, Format: "RAW", UserBucket: {S3Bucket: $bucket, S3Key: $key}}'
)

import_args=(
  ec2 import-snapshot
  --region "$region"
  --client-token "$client_token"
  --description "$description"
  --disk-container "$disk_container"
  --output json
)
if [ -n "$role_name" ]; then
  import_args+=(--role-name "$role_name")
fi

echo "Starting EC2 import-snapshot" >&2
import_json=$(aws "${import_args[@]}")
import_task_id=$(jq -r '.ImportTaskId' <<<"$import_json")
if [ -z "$import_task_id" ] || [ "$import_task_id" = null ]; then
  echo "ERROR: import-snapshot did not return ImportTaskId" >&2
  jq . <<<"$import_json" >&2
  exit 1
fi

echo "Import task: $import_task_id" >&2
deadline=$(( $(date +%s) + timeout_seconds ))
snapshot_id=
while :; do
  task_json=$(
    aws ec2 describe-import-snapshot-tasks \
      --region "$region" \
      --import-task-ids "$import_task_id" \
      --output json
  )
  status=$(jq -r '.ImportSnapshotTasks[0].SnapshotTaskDetail.Status // .ImportSnapshotTasks[0].Status // empty' <<<"$task_json")
  status_message=$(jq -r '.ImportSnapshotTasks[0].SnapshotTaskDetail.StatusMessage // .ImportSnapshotTasks[0].StatusMessage // ""' <<<"$task_json")
  progress=$(jq -r '.ImportSnapshotTasks[0].SnapshotTaskDetail.Progress // ""' <<<"$task_json")
  snapshot_id=$(jq -r '.ImportSnapshotTasks[0].SnapshotTaskDetail.SnapshotId // empty' <<<"$task_json")

  echo "Import status: ${status:-unknown} ${progress:+progress=$progress} ${status_message:+message=$status_message}" >&2

  case "$status" in
    completed)
      if [ -z "$snapshot_id" ]; then
        echo "ERROR: completed import did not report SnapshotId" >&2
        jq . <<<"$task_json" >&2
        exit 1
      fi
      break
      ;;
    deleted|deleting)
      echo "ERROR: import task ended with status $status" >&2
      jq . <<<"$task_json" >&2
      exit 1
      ;;
  esac

  if [ "$(date +%s)" -ge "$deadline" ]; then
    echo "ERROR: timed out waiting for import task $import_task_id" >&2
    jq . <<<"$task_json" >&2
    exit 1
  fi
  sleep "$poll_interval"
done

echo "Waiting for snapshot $snapshot_id" >&2
aws ec2 wait snapshot-completed --region "$region" --snapshot-ids "$snapshot_id"

block_device_mappings="$tmpdir/block-device-mappings.json"
jq -n \
  --arg device "$root_device_name" \
  --arg snapshot "$snapshot_id" \
  --arg volume_type "$volume_type" \
  '[{
    DeviceName: $device,
    Ebs: {
      SnapshotId: $snapshot,
      DeleteOnTermination: true,
      VolumeType: $volume_type
    }
  }]' >"$block_device_mappings"

echo "Registering AMI $name from snapshot $snapshot_id" >&2
image_id=$(
  aws ec2 register-image \
    --region "$region" \
    --name "$name" \
    --description "$description" \
    --architecture x86_64 \
    --root-device-name "$root_device_name" \
    --block-device-mappings "file://$block_device_mappings" \
    --virtualization-type hvm \
    --ena-support \
    --boot-mode uefi \
    --tpm-support v2.0 \
    --output text \
    --query ImageId
)

if [ -z "$image_id" ] || [ "$image_id" = None ]; then
  echo "ERROR: register-image did not return an AMI ID" >&2
  exit 1
fi

tag_args=(
  "Key=Name,Value=$name"
  "Key=dstack:artifact-sha256,Value=$disk_sha256"
  "Key=dstack:import-task-id,Value=$import_task_id"
)
for tag in "${extra_tags[@]}"; do
  if [[ "$tag" != *=* ]]; then
    echo "ERROR: --tag must be KEY=VALUE, got: $tag" >&2
    exit 2
  fi
  tag_args+=("Key=${tag%%=*},Value=${tag#*=}")
done

aws ec2 create-tags \
  --region "$region" \
  --resources "$snapshot_id" "$image_id" \
  --tags "${tag_args[@]}"

echo "Waiting for AMI $image_id" >&2
aws ec2 wait image-available --region "$region" --image-ids "$image_id"

if [ "$delete_s3_object" = true ]; then
  echo "Deleting s3://$s3_bucket/$s3_key" >&2
  aws s3 rm "s3://$s3_bucket/$s3_key" --region "$region" >/dev/null
fi

record=$(
  jq -n \
    --arg schema "dstack-aws-ec2-ami-promotion/v1" \
    --arg generated_at "$generated_at" \
    --arg region "$region" \
    --arg name "$name" \
    --arg description "$description" \
    --arg disk_path "$disk_abs" \
    --arg disk_sha256 "$disk_sha256" \
    --argjson disk_size_bytes "$disk_size_bytes" \
    --arg s3_bucket "$s3_bucket" \
    --arg s3_key "$s3_key" \
    --arg client_token "$client_token" \
    --arg import_task_id "$import_task_id" \
    --arg snapshot_id "$snapshot_id" \
    --arg image_id "$image_id" \
    --arg root_device_name "$root_device_name" \
    --arg volume_type "$volume_type" \
    --argjson delete_s3_object "$delete_s3_object" \
    '{
      schema: $schema,
      generated_at: $generated_at,
      region: $region,
      ami: {
        image_id: $image_id,
        name: $name,
        description: $description,
        boot_mode: "uefi",
        tpm_support: "v2.0",
        architecture: "x86_64",
        virtualization_type: "hvm",
        ena_support: true,
        root_device_name: $root_device_name,
        root_snapshot: $snapshot_id,
        volume_type: $volume_type
      },
      disk: {
        path: $disk_path,
        size: $disk_size_bytes,
        sha256: $disk_sha256
      },
      s3: {
        bucket: $s3_bucket,
        key: $s3_key,
        deleted_after_import: $delete_s3_object
      },
      import_snapshot: {
        client_token: $client_token,
        import_task_id: $import_task_id,
        snapshot_id: $snapshot_id
      }
    }'
)

if [ -n "$output" ]; then
  mkdir -p "$(dirname "$output")"
  printf '%s\n' "$record" >"$output"
fi

printf '%s\n' "$record"
