#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

repo=${1:-$(git rev-parse --show-toplevel)}
run_id=${2:?usage: run-tdxlab-sweep.sh REPOSITORY RUN_ID RUNTIME_MANIFEST [WORKERS]}
runtime_manifest=${3:?usage: run-tdxlab-sweep.sh REPOSITORY RUN_ID RUNTIME_MANIFEST [WORKERS]}
workers=${4:-4}

repo=$(realpath -e -- "$repo")
runtime_manifest=$(realpath -e -- "$runtime_manifest")
plan="$repo/docs/test-plans/core-components-full"
runner="$repo/tools/dstack-test/dstack-test"

# These cases cheaply exercise the substrate that has historically caused
# expensive late failures: guest boot/attestation and clock-dependent
# certificate validation, KMS dependency startup, ACPI input handling, and
# nested-overlay eStargz lifecycle behavior. They run serially and are not
# repeated in the parallel round.
preflight_cases=(
  tc-gos-attestatio-002
  tc-kms-auth-002
  tc-ver-input-plat-007
  tc-int-failure-se-008
  tc-gos-yocto-004
)

args=(
  sweep
  --plan "$plan"
  --run-id "$run_id"
  --workers "$workers"
  --runtime-manifest "$runtime_manifest"
)
for case_id in "${preflight_cases[@]}"; do
  args+=(--preflight-case "$case_id")
done

exec "$runner" "${args[@]}"
