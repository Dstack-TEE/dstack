#!/usr/bin/env bash
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
export PATH="${HOME}/.cargo/bin:${PATH}"

repo=${1:-$(git rev-parse --show-toplevel)}
output=${2:?usage: prepare-run.sh REPOSITORY OUTPUT_JSON [CACHE_ROOT]}
cache_root=${3:-${DSTACK_TEST_CACHE_ROOT:-${XDG_CACHE_HOME:-$HOME/.cache}/dstack-test}}
lab_manifest=${DSTACK_TEST_LAB_MANIFEST:-}

repo=$(realpath -e -- "$repo")
commit=$(git -C "$repo" rev-parse HEAD)
toolchain=$(cd "$repo" && rustc --version)
product_revision=$(git -C "$repo" log -1 --format=%H HEAD -- \
  dstack Cargo.toml Cargo.lock rust-toolchain.toml)
if [[ -z "$product_revision" ]]; then
  product_revision=$commit
fi
export DSTACK_BUILD_GIT_REVISION="git:${product_revision:0:20}"
# Cache product binaries by their actual build inputs, not by the repository
# commit. Documentation, harness, and promotion-only commits must not trigger a
# full workspace rebuild when the product tree and toolchain are unchanged.
tree_fingerprint=$(
  {
    git -C "$repo" ls-tree -r HEAD -- \
      dstack Cargo.toml Cargo.lock rust-toolchain.toml
    git -C "$repo" submodule status --recursive 2>/dev/null || true
    git -C "$repo" diff HEAD --binary -- \
      dstack Cargo.toml Cargo.lock rust-toolchain.toml 2>/dev/null || true
    while IFS= read -r path; do
      printf 'untracked %s ' "$path"
      sha256sum "$repo/$path"
    done < <(
      git -C "$repo" ls-files --others --exclude-standard -- \
        dstack Cargo.toml Cargo.lock rust-toolchain.toml
    )
  } | sha256sum | cut -d' ' -f1
)
cache_key=$(printf 'prepare-run-v4\n%s\n%s\n' "$tree_fingerprint" "$toolchain" | sha256sum | cut -c1-20)
cache_dir="$cache_root/$cache_key"
target_dir="$cache_dir/cargo-target"
prepared_dir="$cache_dir/prepared-binaries"
temporary_dir="$cache_root/tmp"
mkdir -p "$target_dir" "$temporary_dir" "$(dirname "$output")"

export CARGO_TARGET_DIR="$target_dir"
export CARGO_INCREMENTAL=1
export TMPDIR="$temporary_dir"

# A complete immutable snapshot is the cache-hit marker. Avoid invoking Cargo
# at all on a hit: proc-macro Git tracking would otherwise rebuild plan-only
# commits even though the cache key and embedded product revision are stable.
if [[ ! -d "$prepared_dir" ]]; then
# This binary covers Tappd and DstackGuest RPC cases. Other packages are built
# lazily into the same cache unless a case explicitly requires a clean build.
cargo build \
  --manifest-path "$repo/dstack/Cargo.toml" \
  --release --locked \
  -p dstack-guest-agent-simulator \
  -p dstack-tee-simulator \
  -p mock-attestation \
  -p dstack-cli \
  -p dstack-vmm \
  -p dstack-kms \
  -p dstack-gateway \
  -p dstack-verifier \
  -p dstack-util \
  -p supervisor \
  -p supervisor-client \
  -p cert-client \
  --features supervisor-client/cli

# The diagnosis CLI is mounted into historical release containers. Build it as
# a static musl binary so its execution does not depend on the container's
# older glibc while the container still supplies its age-specific QEMU/ACPI data.
cargo build \
  --manifest-path "$repo/dstack/Cargo.toml" \
  --release --locked \
  --target x86_64-unknown-linux-musl \
  -p dstack-mr-cli

simulator="$target_dir/release/dstack-simulator"
for binary in \
  "$simulator" \
  "$target_dir/release/dstack-tee-simulator" \
  "$target_dir/release/dstack-mock-attestation" \
  "$target_dir/release/dstack-kms-sign-cert-fixture" \
  "$target_dir/release/dstack" \
  "$target_dir/release/dstack-vmm" \
  "$target_dir/release/dstack-kms" \
  "$target_dir/release/dstack-gateway" \
  "$target_dir/release/dstack-verifier" \
  "$target_dir/release/dstack-util" \
  "$target_dir/release/supervisor" \
  "$target_dir/release/supervisor-client"
do
  test -x "$binary"
done

# Cargo owns target_dir and may replace release binaries when a later case
# compiles another workspace package.  Runtime fixtures must never point into
# that mutable directory, so publish an immutable snapshot after preparation.
snapshot_tmp="$cache_dir/.prepared-binaries.$$"
mkdir -p "$snapshot_tmp"
for name in dstack-simulator dstack-tee-simulator dstack-mock-attestation dstack-kms-sign-cert-fixture dstack dstack-vmm dstack-kms dstack-gateway dstack-verifier dstack-util supervisor supervisor-client
do
  install -m 0555 "$target_dir/release/$name" "$snapshot_tmp/$name"
done
install -m 0555 "$target_dir/x86_64-unknown-linux-musl/release/dstack-mr" "$snapshot_tmp/dstack-mr-cli"
# The dstack-mr and dstack-mr-cli packages intentionally publish the same
# binary name. Snapshot the machine CLI first, then build and snapshot the
# image-measurement CLI under a distinct immutable runtime name.
cargo build \
  --manifest-path "$repo/dstack/Cargo.toml" \
  --release --locked \
  -p dstack-mr
install -m 0555 "$target_dir/release/dstack-mr" "$snapshot_tmp/dstack-mr-image"
if ! mv -T "$snapshot_tmp" "$prepared_dir" 2>/dev/null; then
  # A prior preparation of the same content-addressed cache may already have
  # published the snapshot.  Never replace it in place.
  for name in dstack-simulator dstack-tee-simulator dstack-mock-attestation dstack-kms-sign-cert-fixture dstack dstack-vmm dstack-kms dstack-gateway dstack-verifier dstack-util supervisor supervisor-client
  do
    cmp -s "$snapshot_tmp/$name" "$prepared_dir/$name"
  done
  cmp -s "$snapshot_tmp/dstack-mr-cli" "$prepared_dir/dstack-mr-cli"
  cmp -s "$snapshot_tmp/dstack-mr-image" "$prepared_dir/dstack-mr-image"
  rm -rf "$snapshot_tmp"
fi
fi

python3 - "$output" "$repo" "$commit" "$product_revision" "$tree_fingerprint" "$toolchain" "$cache_dir" "$target_dir" "$prepared_dir" "$lab_manifest" <<'PY'
import hashlib, json, os, pathlib, sys, tempfile

output, repo, commit, product_revision, tree_fingerprint, toolchain, cache_dir, target_dir, prepared_dir, lab_manifest = sys.argv[1:]
binary_names = {
    "dstack_simulator": "dstack-simulator",
    "dstack_tee_simulator": "dstack-tee-simulator",
    "dstack_mock_attestation": "dstack-mock-attestation",
    "dstack_kms_sign_cert_fixture": "dstack-kms-sign-cert-fixture",
    "dstack_cli": "dstack",
    "dstack_vmm": "dstack-vmm",
    "dstack_kms": "dstack-kms",
    "dstack_gateway": "dstack-gateway",
    "dstack_verifier": "dstack-verifier",
    "dstack_mr_cli": "dstack-mr-cli",
    "dstack_mr_image": "dstack-mr-image",
    "dstack_util": "dstack-util",
    "dstack_supervisor": "supervisor",
    "supervisor_client": "supervisor-client",
}
prepared_binaries = {}
for key, name in binary_names.items():
    binary = pathlib.Path(prepared_dir) / name
    prepared_binaries[key] = {
        "path": str(binary),
        # resolved_path follows cache relocations/symlinks so hot-installs and
        # diagnostics never confuse /tmp vs ~/.cache layouts across machines.
        "resolved_path": str(binary.resolve()),
        "sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
value = {
    "schema_version": "1.0",
    "repository": repo,
    "candidate_commit": commit,
    "product_revision": product_revision,
    "candidate_tree_fingerprint": tree_fingerprint,
    "toolchain": toolchain,
    "cache_dir": cache_dir,
    "cache_dir_resolved": str(pathlib.Path(cache_dir).resolve()),
    "cargo_target_dir": target_dir,
    "prepared_binaries": prepared_binaries,
    "simulator_fixtures": str(pathlib.Path(repo) / "sdk/simulator"),
    "rules": {
        "case_specific_cargo_home": False,
        "case_specific_cargo_target": False,
        "mutable_runtime_is_case_scoped": True,
    },
}
if lab_manifest:
    lab_path = pathlib.Path(lab_manifest).resolve(strict=True)
    lab = json.loads(lab_path.read_text())
    if not isinstance(lab, dict):
        raise SystemExit("lab manifest must contain a JSON object")
    forbidden = set(value).intersection(lab)
    if forbidden:
        raise SystemExit(
            "lab manifest must not override generated keys: "
            + ", ".join(sorted(forbidden))
        )
    value.update(lab)
    value["lab_manifest_source"] = str(lab_path)
    catalog = lab.get("artifact_catalog", {})
    if catalog:
        if not isinstance(catalog, dict):
            raise SystemExit("artifact_catalog must be an object")
        for category, entries in catalog.items():
            if not isinstance(entries, dict):
                raise SystemExit(f"artifact_catalog.{category} must be an object")
            for version, artifact in entries.items():
                if not isinstance(artifact, dict):
                    raise SystemExit(
                        f"artifact_catalog.{category}.{version} must be an object"
                    )
                artifact_path = pathlib.Path(artifact.get("path", "")).resolve(strict=True)
                expected = artifact.get("sha256")
                if not isinstance(expected, str) or len(expected) != 64:
                    raise SystemExit(
                        f"artifact_catalog.{category}.{version} needs sha256"
                    )
                actual = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
                if actual != expected:
                    raise SystemExit(
                        f"artifact digest mismatch: {category}.{version}"
                    )
path = pathlib.Path(output)
with tempfile.NamedTemporaryFile("w", dir=path.parent, delete=False) as f:
    json.dump(value, f, indent=2)
    f.write("\n")
    temporary = f.name
os.replace(temporary, path)
PY

printf 'prepared runtime manifest: %s\n' "$output"
