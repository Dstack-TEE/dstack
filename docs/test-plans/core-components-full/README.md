<!-- SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network> -->
<!-- SPDX-License-Identifier: Apache-2.0 -->
<a id="core-components-test-guide"></a>
# dstack Core Components Full Test Plan

## 1. Objective and scope

This plan is a source-derived, full functional audit of the dstack guest OS, VMM, KMS, gateway, verifier, and their trust and compatibility boundaries. It covers every protobuf RPC method present at authoring time plus non-RPC boot, configuration, storage, networking, cryptographic, measurement, proxy, certificate, cluster, UI, operational, recovery, upgrade, and security behavior found in the component source trees.

The authoritative execution order is `index.json`. Traceability is in
`feature-audit.md`; the raw repository scan is `source-inventory.json` and the
mandatory 214-field configuration matrix is `configuration-inventory.json`, the complete protobuf field matrix is `api-inventory.json`, and reverse file-to-case traceability is `source-coverage-map.json`.
A source reference means the case must be reviewed when that implementation
surface changes. Passing existing unit tests is evidence for a step only when
the case explicitly runs them; it never substitutes for product-level expected
results.

## 2. Repository scope

| Chapter | Primary source roots |
|---|---|
| Guest OS | `os/`, `dstack/guest-agent`, `guest-api`, `supervisor`, `dstack-util`, `local-key-provider`, `tee-simulator` |
| VMM | `dstack/vmm`, `dstack/host-api` |
| KMS | `dstack/kms` including mock/simple/Ethereum authorization implementations |
| Gateway | `dstack/gateway`, `dstack/certbot` |
| Verifier | `dstack/verifier`, `dstack-mr`, `dstack-attest`, image artifact specification |
| Integration | `dstack/tests/e2e`, all cross-component protocols and persisted state |

Before a release run, update `source-inventory.json`, compare RPC/config/source changes with this plan, and add or amend cases before execution.

## 3. Required topology

Prepare isolated namespaces and credentials for:

1. one control host with the candidate repository and `dstack-test`;
2. at least two VMM nodes when cluster/failover behavior is tested;
3. at least three KMS/gateway nodes for rolling-upgrade and partition cases;
4. pinned `v0.5.4`, `v0.5.8`, `v0.5.11`, and candidate guest images;
5. a private OCI registry capable of bearer authentication and fault injection;
6. DNS zones and an ACME staging account, never a production ACME account;
7. controllable HTTP/TCP/TLS/Proxy-Protocol capture backends;
8. an Ethereum development chain and deployed test authorization contract;
9. a fault-injection network supporting latency, loss, partition, and clock-control;
10. a log/artifact sink with secrets redaction.

Use unique run-scoped domains, ports, app IDs, instance names, DNS records, registry tags, and storage paths. Never point destructive Admin, Exit, Clear, Remove, Delete, or certificate cases at production.

## 4. Environment levels

- `UNIT`: repository build/test tools and committed fixtures only.
- `SIMULATOR`: follow `docs/development-without-tee.md`. If the SGX local key provider is unavailable, a no-TEE development guest may independently use `key_provider=tpm`; this does not run local-key-provider in a TPM mode and does not cover SGX local-key-provider behavior.
- `INTEGRATION`: deployed multi-component environment; a TEE simulator is allowed only when the case does not claim hardware properties.
- `HARDWARE`: supported physical TDX/TDX-lite, SEV-SNP, GCP TDX, Nitro TPM, or GPU hardware as named by the case.

Simulation is not confirmation of measured boot, quote/certificate collateral, physical device isolation, sealing, TPM/PCR behavior, GPU attestation, or platform firmware measurements. A simulator result must be labeled simulated. If a hardware case is run only under simulation, report it separately as unconfirmed; do not mark the hardware case PASS.

## 5. Common setup and context

Record actual component commits, image digests, firmware/QEMU/kernel versions, authorization implementation and contract, registry, DNS provider, ACME directory, TEE hardware, and topology once in the run context:

```json
{
  "software_under_test": {
    "repository": "Dstack-TEE/dstack",
    "candidate": "<git-commit>",
    "compatibility_releases": ["v0.5.4", "v0.5.8", "v0.5.11"],
    "guest_images": {
      "v0.5.4": "<digest>", "v0.5.8": "<digest>",
      "v0.5.11": "<digest>", "candidate": "<digest>"
    },
    "vmm": "<version>", "kms": "<version>", "gateway": "<version>", "verifier": "<version>"
  },
  "environment": {
    "level": "HARDWARE",
    "simulated": false,
    "topology": "<run-specific topology reference>"
  }
}
```

Use the generated pRPC clients or a pinned generic pRPC helper. Preserve request and response bodies after redacting credentials. Capture effective TOML, systemd unit state, QEMU command line, VM configuration, image/compose hashes, component health, and synchronized clocks before case execution.

## 6. Execution rules

1. Read this guide, `index.json`, and the current case before acting.
2. Execute cases in index order unless the orchestrator proves a recorded dependency makes a later case meaningless.
3. Every executed case gets an independent Agent session. Commands and raw outputs remain in `session.jsonl`.
4. A case is PASS only when every expected result is fully observed. There is no separate failure criterion.
5. Use BLOCKED only when an external prerequisite prevents the tested behavior from starting.
6. Use SKIPPED only for an authorized omission or a proven dependency consequence, with causal case IDs.
7. Do not change a product configuration merely to force an expected result unless the case instructs that change.
8. Do not restart physical hosts; cases requiring it must use VM/service/device-level recovery or be reported unconfirmed.
9. Stop a destructive case immediately if its target identity is not the isolated run-scoped environment.
10. Continue independent chapters after failures.

### 6.1 Prepared execution environment

Prepare immutable build inputs once before starting a run:

```bash
run_id=<run-id>
automation/prepare-run.sh \
  "$(git rev-parse --show-toplevel)" \
  "results/$run_id/runtime-manifest.json"
```

Export the resulting path as `DSTACK_TEST_RUNTIME_MANIFEST` when invoking the
runner. `dstack-test` also discovers this standard run-relative path
automatically and exports its shared Cargo target and cache directory to every
case Agent.

Every case contains a **Prepared execution knowledge** section. Together with
[`automation/execution-guide.md`](automation/execution-guide.md), it is the
complete initial execution specification. Agents must use the prepared binary
and case-scoped simulator helpers rather than copying Cargo registries,
creating private target trees, browsing earlier sessions, or rebuilding the
same candidate for each RPC method. Clean-build cases remain clean and must not
claim cached output as build evidence.

Run with the live dashboard:

```bash
tools/dstack-test/dstack-test run-plan \
  --plan docs/test-plans/core-components-full \
  --context run-context.json \
  --web \
  -- "Do not restart physical hosts"
```

Resume an interrupted run with its printed run ID:

```bash
tools/dstack-test/dstack-test run-plan \
  --plan docs/test-plans/core-components-full \
  --run-id <run-id> --resume --web
```

## 7. Evidence and redaction

Each logical step must have at least one observed command/tool result in the native Agent session. Attach packet captures, screenshots, QEMU arguments, measurement calculations, certificates, manifests, synchronized cluster snapshots, or long logs under the case result `artifacts/` directory.

Never retain admin tokens, private keys, disk/env plaintext keys, DNS secrets, ACME account keys, Ethereum private keys, reusable cookies, or decrypted application secrets. Quotes, public certificates, public keys, hashes, and redacted configuration may be retained. For a redaction test, record hashes or sentinel-presence checks rather than the secret itself.

## 8. Compatibility policy

Compatibility cases keep VMM on the candidate release by default. Guest images
and online KMS, gateway, and verifier consumers may simultaneously include
`v0.5.4`, `v0.5.8`, `v0.5.11`, and the candidate. Test request distribution,
node loss, restart, state synchronization, old/new client-server directions,
protobuf optional and unknown fields, persisted old state, rolling cutover and
explicit rejection of unsupported combinations. Record the exact tag, commit,
image digest, QEMU, firmware, and backported patch set for every historical
node as a case-level override.

### 8.1 KMS onboarding to the 0.6.0 candidate

Follow the validated matrix in [PR #705](https://github.com/Dstack-TEE/dstack/blob/203e09bcbce27e566f157d2b6ed4657eb949459a/docs/operations/kms-upgrade-plan.md):

| Source KMS | Required path to the 0.6.0 candidate |
|---|---|
| `v0.5.4` | `0.5.4 → 0.5.7 bridge → 0.6.0` |
| `v0.5.8` | direct to `0.6.0` |
| `kms-v0.5.11` | direct to `0.6.0`; record whether PR #693 is included |

The candidate target must boot on its matching candidate OS with **legacy TDX
attestation**, never lite or an `auto` decision that resolves to lite, while an
old source verifies it. The latest VMM must use
`qemu_single_pass_add_pages=true` and `qemu_pic=true`. Both source and target
`mrAggregated` values and the target image hash must be authorized; the source
must download the target verifier archive. A healthy onboard preserves the CA,
root k256 public key, existing application keys, and certificate trust.

Direct `0.5.4 → 0.6.0` is a required negative test: it must fail before key
transfer because 0.5.4 cannot extract the versioned RA-TLS attestation OID.
Use QEMU 9.1.50-era `dstack-acpi-tables` when diagnosing 0.5.4 measurements.
Upgrade gateway only after KMS 0.6.0 key and certificate operations pass, and
retain old KMS/gateway nodes for a tested rollback window.

## 9. Cleanup

Delete run-scoped VMs, workdirs, taps, port mappings, GPU bindings, registry artifacts, DNS records, ACME staging orders, WaveKV objects, authorization contracts/state, temporary KMS nodes, certificates, storage volumes, firewall rules, and fault-injection rules. Verify host devices and services returned to their baseline. Preserve only redacted report artifacts.

## 10. Finalization

```bash
tools/dstack-test/dstack-test validate --plan docs/test-plans/core-components-full --run-id <run-id>
tools/dstack-test/dstack-test render --plan docs/test-plans/core-components-full --run-id <run-id> --output report.html
tools/dstack-test/dstack-test package --plan docs/test-plans/core-components-full --run-id <run-id> --output report.tar.gz
```

The release summary must list every FAIL, BLOCKED, SKIPPED, NOT_RUN, simulation-only result, hardware-unconfirmed item, compatibility gap, and deviation from this plan.
