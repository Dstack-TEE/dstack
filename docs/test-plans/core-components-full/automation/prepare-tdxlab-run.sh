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

for command in cargo curl docker dstack-acpi-tables git jq mkosi npm python3 tar unshare; do
  require_command "$command"
done

user_namespace_ready() {
  unshare --user --map-root-user true >/dev/null 2>&1
}

if ! user_namespace_ready; then
  if [[ $(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null) == 1 ]]; then
    sudo sysctl -q -w kernel.apparmor_restrict_unprivileged_userns=0
  fi
  user_namespace_ready || {
    printf '%s\n' \
      'Unprivileged user namespaces are unavailable after prerequisite setup.' \
      'mkosi cannot build exact-revision guest images in this environment.' >&2
    exit 1
  }
fi

docker_ready() {
  sudo su kvin -c "docker info --format '{{.ServerVersion}}'" >/dev/null 2>&1
}

if ! docker_ready; then
  if command -v systemctl >/dev/null 2>&1; then
    sudo systemctl start docker.service >/dev/null 2>&1 || true
  fi
  docker_ready || {
    printf '%s\n' \
      'Docker daemon is unavailable after attempting to start docker.service.' \
      'Inspect systemctl status docker.service before preparing the test run.' >&2
    exit 1
  }
fi

"$plan/automation/prepare-vmm-hugepages.sh"

acpi_tables_bin=$(realpath -e -- "$(command -v dstack-acpi-tables)")
qemu_data_dir=$(realpath -e -- "$(dirname "$acpi_tables_bin")/../share/qemu")
test -d "$qemu_data_dir" || {
  printf 'missing required dstack-acpi-tables data directory: %s\n' "$qemu_data_dir" >&2
  exit 1
}
test -x "$HOME/.bun/bin/bun" || {
  printf 'missing required command: %s\n' "$HOME/.bun/bin/bun" >&2
  exit 1
}

# Guest-backed cases must exercise binaries from this candidate revision, not
# an older image that happens to carry the same release version. Build both
# flavors once through mkosi's content-addressed component cache, validate the
# embedded provenance, then publish them under immutable revision-derived names.
revision=$(git -C "$repo" rev-parse HEAD)
short_revision=${revision:0:9}
prod_image="dstack-mkosi-$short_revision"
dev_image="dstack-dev-mkosi-$short_revision"
image_store=$(jq -er '.environment.DSTACK_TEST_IMAGE_STORE' "$template")
image_store=$(realpath -e -- "$image_store")
image_matches() {
  local name=$1 expected_dev=$2 image="$image_store/$1"
  local metadata="$image/metadata.json"
  [[ -f $metadata ]] &&
    [[ $(jq -r '.git_revision' "$metadata") == "$revision" ]] &&
    [[ $(jq -r '.backend' "$metadata") == mkosi ]] &&
    [[ $(jq -r '.is_dev' "$metadata") == "$expected_dev" ]] &&
    [[ $(sha256sum "$image/sha256sum.txt" | cut -d' ' -f1) == \
      "$(tr -d '[:space:]' <"$image/digest.txt")" ]] &&
    (cd "$image" && sha256sum --check --status sha256sum.txt)
}
for row in "$prod_image:false" "$dev_image:true"; do
  IFS=: read -r name expected_dev <<<"$row"
  if [[ -e $image_store/$name ]] && ! image_matches "$name" "$expected_dev"; then
    printf 'candidate image name exists with mismatched provenance: %s\n' "$name" >&2
    exit 1
  fi
done
if ! image_matches "$prod_image" false || ! image_matches "$dev_image" true; then
  mkosi_root="$cache_root/mkosi-candidate-$short_revision"
  mkdir -p "$cache_root/tmp/mkosi" "$mkosi_root"
  git_common=$(realpath -e -- "$(git -C "$repo" rev-parse --git-common-dir)")
  original_repo=${git_common%/.git}
  build_repo="$original_repo.worktrees/candidate-image-$short_revision"
  if [[ ! -e $build_repo/.git ]]; then
    mkdir -p "$(dirname "$build_repo")"
    git -C "$repo" worktree add --detach "$build_repo" "$revision"
  fi
  [[ $(git -C "$build_repo" rev-parse HEAD) == "$revision" ]] || {
    printf 'candidate image worktree points at the wrong revision: %s\n' \
      "$build_repo" >&2
    exit 1
  }
  [[ -z $(git -C "$build_repo" status --porcelain) ]] || {
    printf 'candidate image worktree is dirty: %s\n' "$build_repo" >&2
    exit 1
  }
  "$build_repo/os/mkosi/build.sh" lint
  TMPDIR="$cache_root/tmp/mkosi" \
    FLAVORS="prod dev" \
    DSTACK_DEV_CACHE_DIR="$cache_root/mkosi-dev" \
    "$build_repo/os/mkosi/build.sh" image "$mkosi_root"
  find_image_output() {
    local flavor=$1 expected_dev=$2 output_root="$mkosi_root/out/$1"
    local -a candidates=()
    while IFS= read -r -d '' metadata; do
      if [[ $(jq -r '.is_dev' "$metadata") == "$expected_dev" ]]; then
        candidates+=("${metadata%/metadata.json}")
      fi
    done < <(find "$output_root" -mindepth 2 -maxdepth 2 -type f \
      -name metadata.json -print0)
    [[ ${#candidates[@]} -eq 1 ]] || {
      printf 'expected exactly one %s mkosi image output, found %s under %s\n' \
        "$flavor" "${#candidates[@]}" "$output_root" >&2
      return 1
    }
    printf '%s\n' "${candidates[0]}"
  }
  prod_source=$(find_image_output prod false)
  dev_source=$(find_image_output dev true)
  for row in "$prod_source:$prod_image:false" "$dev_source:$dev_image:true"; do
    IFS=: read -r source name expected_dev <<<"$row"
    [[ -e $image_store/$name ]] && continue
    metadata="$source/metadata.json"
    [[ -f $source/sha256sum.txt && -f $metadata ]] || {
      printf 'mkosi output is incomplete: %s\n' "$source" >&2
      exit 1
    }
    [[ $(jq -r '.git_revision' "$metadata") == "$revision" ]] || {
      printf 'mkosi output revision mismatch: %s\n' "$source" >&2
      exit 1
    }
    [[ $(jq -r '.is_dev' "$metadata") == "$expected_dev" ]] || {
      printf 'mkosi output flavor mismatch: %s\n' "$source" >&2
      exit 1
    }
    [[ $(jq -r '.backend' "$metadata") == mkosi ]] || {
      printf 'mkosi output backend mismatch: %s\n' "$source" >&2
      exit 1
    }
    (cd "$source" && sha256sum --check --status sha256sum.txt) || {
      printf 'mkosi output checksum verification failed: %s\n' "$source" >&2
      exit 1
    }
    [[ $(sha256sum "$source/sha256sum.txt" | cut -d' ' -f1) == \
      "$(tr -d '[:space:]' <"$source/digest.txt")" ]] || {
      printf 'mkosi output digest mismatch: %s\n' "$source" >&2
      exit 1
    }
    stage="$image_store/.$name.tmp.$$"
    sudo cp -a -- "$source" "$stage"
    sudo chown -R root:root "$stage"
    sudo mv -- "$stage" "$image_store/$name"
  done
fi
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

python3 - "$template" "$generated_lab" "$plan" "$fixture_root" "$foundry_bin" \
  "$acpi_tables_bin" "$qemu_data_dir" "$prod_image" "$dev_image" <<'PY'
import json
import pathlib
import sys

template, output, plan, full_tdx, foundry_bin, acpi_tables, qemu_data = map(
    pathlib.Path, sys.argv[1:8]
)
prod_image, dev_image = sys.argv[8:]
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
environment["DSTACK_TEST_ACPI_TABLES_BINARY"] = str(acpi_tables.resolve(strict=True))
environment["DSTACK_TEST_QEMU_DATA_DIR"] = str(qemu_data.resolve(strict=True))
environment["DSTACK_TEST_GUEST_IMAGE"] = prod_image
environment["DSTACK_TEST_NO_TEE_GUEST_IMAGE"] = dev_image
environment["DSTACK_TEST_GUEST_PROD_IMAGE"] = prod_image
environment["DSTACK_TEST_GUEST_DEV_IMAGE"] = dev_image
environment["DSTACK_TEST_IDENTITY_ALT_IMAGE"] = prod_image
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
