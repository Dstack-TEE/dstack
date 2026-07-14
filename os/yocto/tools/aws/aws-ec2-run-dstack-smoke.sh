#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  aws-ec2-run-dstack-smoke.sh \
    --ami-id AMI \
    --region REGION \
    --name NAME \
    --shared-snapshot SNAPSHOT \
    (--data-snapshot SNAPSHOT | --data-volume-size GIB) \
    --marker TEXT [--marker TEXT ...] \
    [--instance-type TYPE] \
    [--subnet-id SUBNET] \
    [--security-group-id SG]... \
    [--iam-instance-profile NAME_OR_ARN] \
    [--client-token TOKEN] \
    [--shared-device-name DEVICE] \
    [--data-device-name DEVICE] \
    [--volume-type TYPE] \
    [--metadata-hop-limit N] \
    [--poll-interval SECONDS] \
    [--timeout SECONDS] \
    [--console-output PATH] \
    [--output PATH] \
    [--tag KEY=VALUE]... \
    [--terminate-on-success] \
    [--terminate-on-failure] \
    [--terminate-always]

Launches one EC2 instance from an Attestable dstack AMI, attaches the shared
configuration disk and data disk, polls the EC2 serial console, requires every
explicit --marker to appear, and writes a JSON smoke evidence record.

This script never calls AWS KMS.
USAGE
}

ami_id=
region=
name=
shared_snapshot=
data_snapshot=
data_volume_size=
instance_type=m6i.large
subnet_id=
iam_instance_profile=
client_token=
shared_device_name=/dev/sdf
data_device_name=/dev/sdg
volume_type=gp3
metadata_hop_limit=2
poll_interval=15
timeout_seconds=1800
console_output=
output=
terminate_on_success=false
terminate_on_failure=false
security_group_ids=()
markers=()
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
    --ami-id)
      require_value "$@"
      ami_id=$2
      shift 2
      ;;
    --region)
      require_value "$@"
      region=$2
      shift 2
      ;;
    --name)
      require_value "$@"
      name=$2
      shift 2
      ;;
    --shared-snapshot)
      require_value "$@"
      shared_snapshot=$2
      shift 2
      ;;
    --data-snapshot)
      require_value "$@"
      data_snapshot=$2
      shift 2
      ;;
    --data-volume-size)
      require_value "$@"
      data_volume_size=$2
      shift 2
      ;;
    --marker)
      require_value "$@"
      markers+=("$2")
      shift 2
      ;;
    --instance-type)
      require_value "$@"
      instance_type=$2
      shift 2
      ;;
    --subnet-id)
      require_value "$@"
      subnet_id=$2
      shift 2
      ;;
    --security-group-id)
      require_value "$@"
      security_group_ids+=("$2")
      shift 2
      ;;
    --iam-instance-profile)
      require_value "$@"
      iam_instance_profile=$2
      shift 2
      ;;
    --client-token)
      require_value "$@"
      client_token=$2
      shift 2
      ;;
    --shared-device-name)
      require_value "$@"
      shared_device_name=$2
      shift 2
      ;;
    --data-device-name)
      require_value "$@"
      data_device_name=$2
      shift 2
      ;;
    --volume-type)
      require_value "$@"
      volume_type=$2
      shift 2
      ;;
    --metadata-hop-limit)
      require_value "$@"
      metadata_hop_limit=$2
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
    --console-output)
      require_value "$@"
      console_output=$2
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
    --terminate-on-success)
      terminate_on_success=true
      shift
      ;;
    --terminate-on-failure)
      terminate_on_failure=true
      shift
      ;;
    --terminate-always)
      terminate_on_success=true
      terminate_on_failure=true
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

if [ -z "$ami_id" ] || [ -z "$region" ] || [ -z "$name" ] || [ -z "$shared_snapshot" ]; then
  usage
  exit 2
fi

if [ "${#markers[@]}" -eq 0 ]; then
  echo "ERROR: at least one --marker is required" >&2
  exit 2
fi

if [ -n "$data_snapshot" ] && [ -n "$data_volume_size" ]; then
  echo "ERROR: use either --data-snapshot or --data-volume-size, not both" >&2
  exit 2
fi

if [ -z "$data_snapshot" ] && [ -z "$data_volume_size" ]; then
  echo "ERROR: one of --data-snapshot or --data-volume-size is required" >&2
  exit 2
fi

for integer_arg in poll_interval timeout_seconds metadata_hop_limit; do
  value=${!integer_arg}
  case "$value" in
    ''|*[!0-9]*)
      echo "ERROR: $integer_arg must be an integer" >&2
      exit 2
      ;;
  esac
done

if [ "$poll_interval" -eq 0 ]; then
  echo "ERROR: --poll-interval must be greater than zero" >&2
  exit 2
fi

if [ -n "$data_volume_size" ]; then
  case "$data_volume_size" in
    ''|*[!0-9]*)
      echo "ERROR: --data-volume-size must be an integer GiB value" >&2
      exit 2
      ;;
  esac
fi

for required in aws jq date sha256sum mktemp sed; do
  if ! command -v "$required" >/dev/null 2>&1; then
    echo "ERROR: required command not found: $required" >&2
    exit 2
  fi
done

tmpdir=$(mktemp -d)
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT

if [ -z "$client_token" ]; then
  safe_name=$(printf '%s' "$name" | sed 's/[^A-Za-z0-9_-]/-/g' | cut -c1-48)
  client_token="${safe_name}-$(date -u +%Y%m%d%H%M%S)"
fi

if [ -z "$console_output" ]; then
  console_output="$tmpdir/console.txt"
else
  mkdir -p "$(dirname "$console_output")"
fi

block_device_mappings=$(
  jq -cn \
    --arg shared_device "$shared_device_name" \
    --arg shared_snapshot "$shared_snapshot" \
    --arg data_device "$data_device_name" \
    --arg data_snapshot "$data_snapshot" \
    --arg data_volume_size "$data_volume_size" \
    --arg volume_type "$volume_type" '
      [
        {
          DeviceName: $shared_device,
          Ebs: {
            SnapshotId: $shared_snapshot,
            DeleteOnTermination: true,
            VolumeType: $volume_type
          }
        },
        {
          DeviceName: $data_device,
          Ebs: (
            if $data_snapshot != "" then
              {
                SnapshotId: $data_snapshot,
                DeleteOnTermination: true,
                VolumeType: $volume_type
              }
            else
              {
                VolumeSize: ($data_volume_size | tonumber),
                DeleteOnTermination: true,
                VolumeType: $volume_type
              }
            end
          )
        }
      ]'
)

tag_array=$(
  {
    printf '%s\n' "Name=$name"
    printf '%s\n' "Purpose=dstack-aws-live-smoke"
    for tag in "${extra_tags[@]}"; do
      printf '%s\n' "$tag"
    done
  } |
    jq -Rn '
      [inputs
       | select(length > 0)
       | capture("(?<Key>[^=]+)=(?<Value>.*)")]
    '
)

tag_specifications=$(
  jq -cn \
    --argjson tags "$tag_array" '
      [
        {ResourceType: "instance", Tags: $tags},
        {ResourceType: "volume", Tags: $tags}
      ]'
)

metadata_options="HttpEndpoint=enabled,HttpTokens=required,HttpPutResponseHopLimit=$metadata_hop_limit"

run_args=(
  ec2 run-instances
  --region "$region"
  --image-id "$ami_id"
  --instance-type "$instance_type"
  --count 1
  --client-token "$client_token"
  --block-device-mappings "$block_device_mappings"
  --metadata-options "$metadata_options"
  --tag-specifications "$tag_specifications"
  --output json
)

if [ -n "$subnet_id" ]; then
  run_args+=(--subnet-id "$subnet_id")
fi

if [ "${#security_group_ids[@]}" -gt 0 ]; then
  run_args+=(--security-group-ids "${security_group_ids[@]}")
fi

if [ -n "$iam_instance_profile" ]; then
  if [[ "$iam_instance_profile" == arn:* ]]; then
    run_args+=(--iam-instance-profile "Arn=$iam_instance_profile")
  else
    run_args+=(--iam-instance-profile "Name=$iam_instance_profile")
  fi
fi

echo "Launching $name from $ami_id in $region" >&2
run_json=$(aws "${run_args[@]}")
instance_id=$(jq -r '.Instances[0].InstanceId' <<<"$run_json")
if [ -z "$instance_id" ] || [ "$instance_id" = null ]; then
  echo "ERROR: run-instances did not return an instance id" >&2
  jq . <<<"$run_json" >&2
  exit 1
fi

echo "Instance: $instance_id" >&2
aws ec2 wait instance-running --region "$region" --instance-ids "$instance_id"

terminate_instance() {
  local reason=$1
  echo "Terminating $instance_id ($reason)" >&2
  aws ec2 terminate-instances \
    --region "$region" \
    --instance-ids "$instance_id" \
    --output json >/dev/null
}

write_evidence() {
  local status=$1
  local termination=$2
  local console_sha generated_at marker_json describe_json

  generated_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  if [ -s "$console_output" ]; then
    console_sha=$(sha256sum "$console_output" | awk '{print $1}')
  else
    console_sha=
  fi
  marker_json=$(printf '%s\n' "${markers[@]}" | jq -Rn '[inputs]')
  describe_json=$(
    aws ec2 describe-instances \
      --region "$region" \
      --instance-ids "$instance_id" \
      --output json
  )

  jq -n \
    --arg schema "dstack-aws-ec2-live-smoke/v1" \
    --arg generated_at "$generated_at" \
    --arg status "$status" \
    --arg region "$region" \
    --arg ami_id "$ami_id" \
    --arg name "$name" \
    --arg instance_id "$instance_id" \
    --arg instance_type "$instance_type" \
    --arg shared_snapshot "$shared_snapshot" \
    --arg data_snapshot "$data_snapshot" \
    --arg data_volume_size "$data_volume_size" \
    --arg shared_device_name "$shared_device_name" \
    --arg data_device_name "$data_device_name" \
    --arg client_token "$client_token" \
    --arg console_output "$console_output" \
    --arg console_sha256 "$console_sha" \
    --arg termination "$termination" \
    --argjson markers "$marker_json" \
    --argjson run_instances "$run_json" \
    --argjson describe_instances "$describe_json" '
      {
        schema: $schema,
        generated_at: $generated_at,
        status: $status,
        region: $region,
        ami_id: $ami_id,
        name: $name,
        instance_id: $instance_id,
        instance_type: $instance_type,
        block_devices: {
          shared: {
            device_name: $shared_device_name,
            snapshot: $shared_snapshot
          },
          data: {
            device_name: $data_device_name,
            snapshot: (if $data_snapshot == "" then null else $data_snapshot end),
            volume_size_gib: (if $data_volume_size == "" then null else ($data_volume_size | tonumber) end)
          }
        },
        client_token: $client_token,
        required_markers: $markers,
        console_output: {
          path: $console_output,
          sha256: (if $console_sha256 == "" then null else $console_sha256 end)
        },
        termination: $termination,
        aws: {
          run_instances: $run_instances,
          describe_instances: $describe_instances
        }
      }'
}

deadline=$(( $(date +%s) + timeout_seconds ))
last_status=timeout
while :; do
  aws ec2 get-console-output \
    --region "$region" \
    --instance-id "$instance_id" \
    --latest \
    --output json |
    jq -r '.Output // ""' >"$console_output"

  all_markers_found=true
  for marker in "${markers[@]}"; do
    if ! grep -F -- "$marker" "$console_output" >/dev/null; then
      all_markers_found=false
      break
    fi
  done

  if [ "$all_markers_found" = true ]; then
    last_status=passed
    break
  fi

  if [ "$(date +%s)" -ge "$deadline" ]; then
    last_status=timeout
    break
  fi

  echo "Waiting for console markers on $instance_id" >&2
  sleep "$poll_interval"
done

termination=kept
if [ "$last_status" = passed ] && [ "$terminate_on_success" = true ]; then
  terminate_instance success
  termination=terminated
elif [ "$last_status" != passed ] && [ "$terminate_on_failure" = true ]; then
  terminate_instance "$last_status"
  termination=terminated
fi

evidence=$(write_evidence "$last_status" "$termination")
if [ -n "$output" ]; then
  mkdir -p "$(dirname "$output")"
  jq . <<<"$evidence" >"$output"
else
  jq . <<<"$evidence"
fi

if [ "$last_status" != passed ]; then
  echo "ERROR: smoke test did not observe all required markers before timeout" >&2
  exit 1
fi
