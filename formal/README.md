# Formal proofs

Lean 4 models of security-relevant logic in the KMS, gateway and guest OS,
with machine-checked proofs. Core Lean only (no Mathlib).

```sh
cd formal && lake build
```

## Scope

| Module | Rust / Solidity modeled | Main results |
| --- | --- | --- |
| `Kms.RootEpoch` | `root_epoch.rs: chain_hashes`, `servable_epoch`, `authorized_epoch`, `ensure_handover_registered`, `DstackKms.sol` root epochs | contract invariants; the contract stores the Rust chain hashes; a served epoch binds the registered keys; rotation never collides with a pending epoch |
| `Kms.KeyDerivation` | `kms/src/crypto.rs`, key derivations in `main_service.rs` | HKDF inputs of distinct derivations never coincide; signed preimages are prefix-free |
| `Kms.RaTlsEncoding` | `ra-tls/src/api_v1.rs` | length-prefixed encodings are injective; derivation info and claims never collide |
| `Kms.KeyRelease` | `ensure_key_release_allowed`, `get_app_key`, `sign_cert`, handover | a released key implies every attestation, authorization, epoch and platform check passed; the self-authorization cache is per operation |
| `Gateway.Import` | `kv/import.rs` (#1604) | accepted instances are injective on IP and WireGuard key, carry no gateway key, are order-independent, and partition the input; nodes agree once their own keys have replicated; key squatting: counterexample without proof of possession, key binding stable with it (#1615, modeled abstractly) |
| `Gateway.IpAlloc` | `alloc_ip`, `valid_ip`, `release_ip` (#1605), `forget_instance`, reload, rebuild | allocation returns a free valid IP, none iff exhausted; a live instance's IP is never reissued, even when shared during a conflict loser's grace period; equal KV contents give equal accepted sets under `PoolsClear` (an assumption; #1606 only warns) |
| `Gateway.CertLock` | `kv/mod.rs: try_acquire_lock`, `release_lock`, `lease_still_held` (#1599–#1601) | single-node ownership under any clock and force releases; single-node exclusion; cross-node, a release or lease-guarded commit never overrides a successor's lease (successor clock within the drift bound); limitations: replication gap, skew beyond the drift bound, cross-node force release |
| `Gateway.PortPolicy`, `CertStore`, `Ingress`, `HealthCheck` | `port_policy.rs`, `cert_store.rs` (#1603), `parse_dst_info`, `apply_hysteresis`, backend selection | fail-closed port policy; wildcards cover exactly one non-empty label; canonical port spelling; hysteresis and selection soundness |
| `Gateway.Sni`, `MsgpackSkip` | `proxy/sni.rs` (#1602), `kv/compat.rs: skip_value` | the SNI lies within every declared enclosing block; `skip_value` stays in bounds and skips exactly one value |
| `Guest.EventLog` | `cc-eventlog/src/runtime_events.rs`, `tdx.rs: validate_v2_preimages` | V1 preimages are injective for colon-free names (`RuntimeEvent::validate`); V2 JSON is injective; replay binds the log |
| `Guest.BootTrace` | `dstack-util/src/system_setup.rs` boot sequence | event order; keys requested only after `boot-mr-done`; every config value used is measured |
| `Guest.MrConfig`, `InstanceId`, `EnvFile`, `Policy` | `mr_config.rs`, `config_id_verifier.rs`, instance-id derivation, `parse_env_file.rs`, compose requirement checks | injective encodings; exact verifier acceptance conditions; env round trip; fail-closed checks |
| `Vmm.Lifecycle`, `Safety`, `Traces` | `vmm/src/app.rs` (start, stop, removal, reloads, guest power-off, auto-restart), `main_service.rs` RPCs, `app/workdir.rs`, `supervisor.rs: deploy` (#1609–#1614) | one VM id, async ops as steps between awaits, crash and boot reload: removal holding the lock blocks deploys; one running process; deletion only with nothing running and netd released; recovery stops only marked or missing workdirs; reload never removes a VM being created; power-off never cancels a later start; counterexamples: a deploy can land while removing, cancellation at `deploy` breaks single-process, the reload RPC's start overrides an acknowledged stop |

Each module header lists the functions it mirrors, its assumptions, and what it
leaves out. Several Rust unit tests are restated as `example`s.

## Trust base

- Models are written by hand from the code, not extracted. A change to the
  modeled Rust or Solidity code should update the model.
- Hash, KDF and signature functions are parameters. Idealized properties such
  as injectivity (standing in for collision resistance) are explicit theorem
  hypotheses, never axioms.
- CI rejects `sorry`, `axiom`, `native_decide` and unchecked code; warnings are
  errors.
