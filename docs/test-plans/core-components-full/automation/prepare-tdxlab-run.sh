#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export PATH="$HOME/.cargo/bin:$HOME/.bun/bin:$PATH"

repo=${1:-$(git rev-parse --show-toplevel)}
output=${2:?usage: prepare-tdxlab-run.sh REPOSITORY OUTPUT_JSON [CACHE_ROOT]}
cache_root=${3:-${DSTACK_TEST_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack-test}}

repo=$(realpath -e -- "$repo")
plan="$repo/docs/test-plans/core-components-full"
template="$plan/automation/tdxlab-manifest.json"
generated_lab="${output%.json}.lab.json"
fixture_root="$cache_root/fixtures/verifier/full-tdx-0.5.4.1"
image_hash=14ad42d0270b444eaeb53918a5a94d9b17eec7a817cd336173b17c5327541c67
foundry_version=v1.7.1
foundry_sha256=cf7e688ed0c4c48adffca788b496076e31060b67ac5afe1e43dbb5499c20c88b
foundry_bin="$cache_root/tools/foundry-$foundry_version"
mkdir -p "$cache_root/tmp"

require_command() {
  command -v "$1" >/dev/null || {
    printf 'missing required command: %s\n' "$1" >&2
    exit 1
  }
}

for command in cargo curl git jq npm python3 tar; do
  require_command "$command"
done
test -x "$HOME/.bun/bin/bun" || {
  printf 'missing required command: %s\n' "$HOME/.bun/bin/bun" >&2
  exit 1
}
if [[ ! -x "$foundry_bin/forge" ]]; then
  archive=$(mktemp "$cache_root/tmp/foundry.XXXXXX.tar.gz")
  trap 'rm -f "$archive"' EXIT
  mkdir -p "$foundry_bin"
  curl --fail --location --retry 3 --output "$archive" \
    "https://github.com/foundry-rs/foundry/releases/download/$foundry_version/foundry_${foundry_version}_linux_amd64.tar.gz"
  echo "$foundry_sha256  $archive" | sha256sum --check --status
  tar -xzf "$archive" -C "$foundry_bin"
  test -x "$foundry_bin/forge"
fi
export PATH="$foundry_bin:$PATH"

# Only initialize the contract fixtures used by the scripted KMS cases. The
# much larger Yocto submodules are unrelated to this run preparation.
git -C "$repo" submodule update --init --depth 1 -- \
  dstack/kms/auth-eth/lib/forge-std \
  dstack/kms/auth-eth/lib/openzeppelin-contracts-upgradeable \
  dstack/kms/auth-eth/lib/openzeppelin-foundry-upgrades

# Materialize locked JavaScript dependencies before workers start. Installing
# into shared package directories from concurrent cases races and previously
# left auth services without tsc or a healthy listener.
(
  cd "$repo/dstack/kms/auth-simple"
  "$HOME/.bun/bin/bun" install --frozen-lockfile
)
(
  cd "$repo/dstack/kms/auth-eth-bun"
  "$HOME/.bun/bin/bun" install --frozen-lockfile
)
(
  cd "$repo/dstack/kms/auth-eth"
  npm ci --ignore-scripts
)

# This public, immutable image is required by four verifier harnesses. Bind the
# extracted directory to its published digest before exposing it to a case.
if [[ ! -f "$fixture_root/sha256sum.txt" ]] || \
   [[ $(sha256sum "$fixture_root/sha256sum.txt" | cut -d' ' -f1) != "$image_hash" ]]; then
  archive=$(mktemp "$cache_root/tmp/full-tdx.XXXXXX.tar.gz")
  trap 'rm -f "$archive"' EXIT
  rm -rf "$fixture_root"
  mkdir -p "$fixture_root"
  curl --fail --location --retry 3 --output "$archive" \
    "https://download.dstack.org/os-images/mr_${image_hash}.tar.gz"
  tar -xzf "$archive" -C "$fixture_root"
  test "$(sha256sum "$fixture_root/sha256sum.txt" | cut -d' ' -f1)" = "$image_hash"
fi

# The compose-validation case deliberately runs without registry access and
# therefore needs this public base image present before fixture isolation.
if ! sudo su kvin -c "docker image inspect alpine:latest" >/dev/null 2>&1; then
  sudo su kvin -c "docker pull alpine:latest"
fi

python3 - "$template" "$generated_lab" "$plan" "$fixture_root" "$foundry_bin" <<'PY'
import json
import pathlib
import sys

template, output, plan, full_tdx, foundry_bin = map(pathlib.Path, sys.argv[1:])
value = json.loads(template.read_text())
environment = value.setdefault("environment", {})
providers = {
    "DSTACK_TEST_PROVIDER_TDXLAB_ISOLATED": "tdxlab-isolated.py",
    "DSTACK_TEST_PROVIDER_ISOLATED_COMPONENT": "isolated-component.py",
    "DSTACK_TEST_PROVIDER_HARDWARE_POOL": "hardware-pool.py",
    "DSTACK_TEST_PROVIDER_VERSION_MATRIX": "version-matrix.py",
}
for variable, name in providers.items():
    path = (plan / "fixtures/providers" / name).resolve(strict=True)
    if not path.is_file():
        raise SystemExit(f"provider is not a file: {path}")
    environment[variable] = str(path)
environment["DSTACK_TEST_VERIFIER_FULL_TDX_IMAGE_DIR"] = str(
    full_tdx.resolve(strict=True)
)
path_prepend = value.setdefault("environment_path_prepend", [])
foundry_path = str(foundry_bin.resolve(strict=True))
if foundry_path not in path_prepend:
    path_prepend.insert(0, foundry_path)
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")
PY

export DSTACK_TEST_LAB_MANIFEST="$generated_lab"
"$plan/automation/prepare-run.sh" "$repo" "$output" "$cache_root"
printf 'prepared tdxlab prerequisites and runtime manifest: %s\n' "$output"
