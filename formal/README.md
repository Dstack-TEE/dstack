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
| `Gateway.Import` | `kv/import.rs` | accepted instances are injective on IP and WireGuard key, order-independent, and partition the input |
| `Gateway.IpAlloc` | `alloc_ip`, `valid_ip`, `forget_instance` | allocation returns a free valid IP, none iff exhausted; live IPs stay distinct |
| `Gateway.CertLock` | `kv/mod.rs: try_acquire_lock`, `release_lock` | single-node exclusion and ownership; counterexample: two nodes hold the lock during a replication gap |
| `Gateway.PortPolicy`, `CertStore`, `Ingress`, `HealthCheck` | `port_policy.rs`, `cert_store.rs`, `parse_dst_info`, `apply_hysteresis`, backend selection | fail-closed port policy; single-label wildcards; canonical port spelling; hysteresis and selection soundness |
| `Gateway.Sni`, `MsgpackSkip` | `proxy/sni.rs`, `kv/compat.rs: skip_value` | the SNI is a slice of the input; `skip_value` stays in bounds and skips exactly one value |
| `Guest.EventLog` | `cc-eventlog/src/runtime_events.rs`, `tdx.rs: validate_v2_preimages` | V1 preimages are injective for colon-free names (`RuntimeEvent::validate`); V2 JSON is injective; replay binds the log |
| `Guest.BootTrace` | `dstack-util/src/system_setup.rs` boot sequence | event order; keys requested only after `boot-mr-done`; every config value used is measured |
| `Guest.MrConfig`, `InstanceId`, `EnvFile`, `Policy` | `mr_config.rs`, `config_id_verifier.rs`, instance-id derivation, `parse_env_file.rs`, compose requirement checks | injective encodings; exact verifier acceptance conditions; env round trip; fail-closed checks |

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
