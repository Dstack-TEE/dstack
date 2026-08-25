// SPDX-FileCopyrightText: © 2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

// The `dstack.guest.v1` surface: the recommended client, and what the
// unsuffixed `DstackClient` names since 0.6.0.

import { send_rpc_request } from './send-rpc-request'
import { to_hex, throwOnRpcError, resolveDstackEndpoint } from './shared'

/**
 * Decode a wire hex string into the bytes the field is declared as.
 *
 * Every `bytes` field in the v1 proto travels as lowercase hex and surfaces
 * here as a `Uint8Array`, so this runs on all of them. A missing field is
 * proto3's empty default, not an error.
 */
function from_hex(value: string | undefined): Uint8Array {
  return new Uint8Array(Buffer.from(value ?? '', 'hex'))
}

export interface IssueCertOptionsV1 {
  subject?: string;
  altNames?: string[];
  usageRaTls?: boolean;
  usageServerAuth?: boolean;
  usageClientAuth?: boolean;
  withAppInfo?: boolean;
  // Certificate validity start (seconds since UNIX epoch).
  notBefore?: number;
  // Certificate validity end (seconds since UNIX epoch).
  notAfter?: number;
}

export interface IssueCertResponseV1 {
  __name__: Readonly<'IssueCertResponseV1'>

  /**
   * The private key the agent generated for this certificate, PEM-encoded.
   *
   * PEM and nothing else. v0 attached a raw-bytes accessor here, but it existed
   * to feed the key into the blockchain adapters, and v1 has no chain-flavored
   * surface: this is TLS material, PEM is what a TLS stack takes, and a caller
   * who genuinely wants DER converts it with a standard library. The other
   * three SDKs' v1 clients return the PEM string alone too.
   */
  key: string
  /** The certificate chain, leaf first, each entry PEM-encoded. */
  certificate_chain: string[]
}

export interface GetKeyResponseV1 {
  __name__: Readonly<'GetKeyResponseV1'>

  /** The derived private key: 32 raw bytes for both supported algorithms. */
  key: Uint8Array
  /** SEC1 compressed (33 bytes) for secp256k1, raw (32 bytes) for ed25519. */
  public_key: Uint8Array
  /** Two links: the app root key over the v1 key claim, then the KMS root key. */
  signature_chain: Uint8Array[]
}

export interface AttestResponseV1 {
  __name__: Readonly<'AttestResponseV1'>

  attestation: Uint8Array

  /**
   * The GPU evidence nvattest recorded at boot, in the same bundle shape
   * {@link DstackClientV1.attestGpu} returns, so one parser serves both. Empty
   * unless the request asked for it and the guest has boot-time output --
   * absence is the empty array, not a sentinel.
   *
   * Not bound to `report_data`: nvattest ran at boot against its own nonce.
   * Bind it by replaying the runtime event log and comparing sha256 of each
   * bundle's `evidence` against `evidence_sha256` in the measured
   * `gpu-attestation` event.
   */
  boottime_gpu_evidence: GpuEvidenceBundleV1[]
}

/**
 * One vendor's GPU evidence, however it was obtained.
 *
 * Shared by {@link DstackClientV1.attestGpu} and
 * {@link AttestResponseV1.boottime_gpu_evidence}; dispatch on `vendor` and
 * `format`, because the two sources answer different questions and a verifier
 * for one does not appraise the other:
 *
 * - `nvidia-nvattest-collect-evidence-json-v1` -- collected on demand by
 *   `attestGpu`, against the nonce you passed.
 * - `nvidia-nvattest-boottime-json-v1` -- the record written at boot, carried
 *   by `attest`.
 */
export interface GpuEvidenceBundleV1 {
  /** Stable GPU vendor identifier, for example `nvidia`. */
  vendor: string
  /** Vendor-specific evidence format and version. */
  format: string
  /**
   * Opaque vendor-native evidence bytes, exactly as the vendor emitted them
   * (hex-encoded by the JSON RPC, decoded here).
   *
   * Byte-exact by design: for a boot-time bundle the binding rule is sha256
   * over precisely these bytes, compared against `evidence_sha256` in the
   * measured `gpu-attestation` event, so parsing and re-serialising the JSON
   * breaks the comparison.
   */
  evidence: Uint8Array
}

/** A bundle as it arrives, before `evidence` is decoded. */
type GpuEvidenceBundleV1Wire = Omit<GpuEvidenceBundleV1, 'evidence'> & { evidence: string }

export interface AttestGpuResponseV1 {
  __name__: Readonly<'AttestGpuResponseV1'>

  bundles: GpuEvidenceBundleV1[]
}

/**
 * Identity and configuration. Not attestation.
 *
 * The measurement registers and the event log are deliberately absent -- they
 * belong to `attest()`, which returns them quote-backed. Nothing here arrives
 * with a quote behind it, so confirm anything you rely on against an
 * attestation.
 *
 * `app_id`, `compose_hash`, `instance_id`, `device_id`, `os_image_hash` and
 * `mr_aggregated` are `bytes` in the proto and `Uint8Array` here, lowercase hex
 * only on the wire; the rest are plain strings, with the three document fields
 * carrying JSON owned by someone else (see `docs/guest-api-v1.md`).
 */
export interface InfoResponseV1 {
  __name__: Readonly<'InfoResponseV1'>

  app_id: Uint8Array
  app_name: string
  compose_hash: Uint8Array
  /**
   * The app-compose document, verbatim. `compose_hash` is sha256 over exactly
   * these bytes, so do not parse and re-serialize before hashing: key order,
   * whitespace and unknown fields all change the digest.
   */
  app_compose: string
  instance_id: Uint8Array
  /** Identifies the host machine, not this instance. */
  device_id: Uint8Array
  os_image_hash: Uint8Array
  mr_aggregated: Uint8Array
  vm_config: string
  key_provider_info: string
  cloud_vendor: string
  cloud_product: string
}

/**
 * `InfoResponseV1` as it arrives: identity fields hex, everything else final.
 *
 * `os_image_hash` and `mr_aggregated` are `optional` on the wire, so an older
 * agent may omit them entirely rather than send an empty string.
 */
type InfoResponseV1Wire =
  Omit<InfoResponseV1, '__name__' | 'app_id' | 'compose_hash' | 'instance_id'
    | 'device_id' | 'os_image_hash' | 'mr_aggregated'>
  & {
    app_id: string
    compose_hash: string
    instance_id: string
    device_id: string
    os_image_hash?: string
    mr_aggregated?: string
  }

export interface VersionResponseV1 {
  __name__: Readonly<'VersionResponseV1'>

  version: string
  rev: string
}

/**
 * Decode the bundles a v1 RPC returned.
 *
 * Shared by `attest` and `attestGpu` so both hand back the same object shape,
 * which is the point of the wire message being shared.
 */
function to_gpu_evidence_bundles(
  bundles: GpuEvidenceBundleV1Wire[] | undefined,
): GpuEvidenceBundleV1[] {
  return (bundles ?? []).map(bundle => Object.freeze({
    ...bundle,
    evidence: from_hex(bundle.evidence),
  }))
}

/**
 * Client for `dstack.guest.v1`, served at `/v1/<Method>` by dstack 0.6.0 and later.
 *
 * Six methods, no more: v1 serves only what needs the TEE -- deriving keys from
 * the app root key, and attesting. `sign`, `verify`, `getQuote`, `gpuInfo` and
 * `emitEvent` are absent by design, not by oversight; see `docs/guest-api-v1.md`.
 *
 * A v1 key is NOT the v0 key of the same name. v1 derives under its own HKDF
 * salt and binds the algorithm into the derivation, so `getKey('storage-encryption',
 * 'secp256k1')` here returns different material than `DstackClientV0.getKey`
 * ever did, and secp256k1 and ed25519 no longer share one secret. There is no
 * compatibility mode.
 *
 * An agent that predates v1 has no `/v1` mount, so it answers with a plain
 * HTTP 404 page rather than a JSON error. `version()` is the cheapest probe.
 */
export class DstackClientV1 {
  protected endpoint: string

  constructor(endpoint: string | undefined = undefined) {
    this.endpoint = resolveDstackEndpoint(endpoint)
  }

  /**
   * Issue a certificate for this application.
   *
   * The key is freshly generated on every call and is not derived from the app
   * identity: two identical requests produce two unrelated keys. Use
   * {@link getKey} for stable, attestable material.
   */
  async issueCert(options: IssueCertOptionsV1 = {}): Promise<IssueCertResponseV1> {
    const {
      subject = '',
      altNames = [],
      usageRaTls = false,
      usageServerAuth = true,
      usageClientAuth = false,
      withAppInfo = false,
      notBefore,
      notAfter,
    } = options;

    const raw: Record<string, any> = {
      subject,
      usage_ra_tls: usageRaTls,
      usage_server_auth: usageServerAuth,
      usage_client_auth: usageClientAuth,
      with_app_info: withAppInfo,
    }
    if (altNames && altNames.length) {
      raw['alt_names'] = altNames
    }
    // Both are `optional` on the wire, so send them only when asked for rather
    // than pinning a validity window the caller never chose.
    if (notBefore !== undefined) {
      raw['not_before'] = notBefore
    }
    if (notAfter !== undefined) {
      raw['not_after'] = notAfter
    }
    const result = await send_rpc_request<{ key: string, certificate_chain: string[] }>(
      this.endpoint, '/v1/IssueCert', JSON.stringify(raw))
    throwOnRpcError(result)
    return Object.freeze({
      ...result,
      __name__: 'IssueCertResponseV1' as const,
    })
  }

  /**
   * Derive an application key from `(domain, algorithm)`.
   *
   * `domain` is an opaque domain-separation string, not a DNS name and not a
   * path: derivation is flat, so `a/b` is not a child of `a` and no key derived
   * here can derive another.
   *
   * @param domain Caller-chosen domain-separation string. May be empty.
   * @param algorithm Exactly `secp256k1` or `ed25519`. No default, no `k256` alias.
   */
  async getKey(domain: string, algorithm: string): Promise<GetKeyResponseV1> {
    // v0 defaulted an empty algorithm to secp256k1, which let a typo hand back a
    // key of the wrong type under a name the caller thought meant something else.
    if (!algorithm) {
      throw new Error('algorithm is required, use "secp256k1" or "ed25519"')
    }
    const payload = JSON.stringify({ domain, algorithm })
    const result = await send_rpc_request<{ key: string, public_key: string, signature_chain: string[] }>(
      this.endpoint, '/v1/GetKey', payload)
    throwOnRpcError(result)
    return Object.freeze({
      key: from_hex(result.key),
      public_key: from_hex(result.public_key),
      signature_chain: result.signature_chain.map(from_hex),
      __name__: 'GetKeyResponseV1' as const,
    })
  }

  /**
   * Produce a versioned attestation over the given report data.
   *
   * The only CVM attestation entry point in v1: the attestation already carries
   * the TDX quote and the event log, so there is no separate `getQuote`.
   *
   * @param report_data 1 to 64 bytes, zero-padded on the right to 64 by the agent.
   * @param include_boottime_gpu_evidence Also return the boot-time GPU evidence,
   * as the same {@link GpuEvidenceBundleV1} list `attestGpu` returns, so a
   * verifier gets both in one round trip. It is not bound to `report_data`.
   */
  async attest(
    report_data: string | Buffer | Uint8Array,
    include_boottime_gpu_evidence: boolean = false,
  ): Promise<AttestResponseV1> {
    const hex = to_hex(report_data)
    if (hex.length === 0) {
      throw new Error('report data must not be empty')
    }
    if (hex.length > 128) {
      throw new Error(`report data must be at most 64 bytes, but received ${hex.length / 2}`)
    }
    const payload = JSON.stringify({ report_data: hex, include_boottime_gpu_evidence })
    const result = await send_rpc_request<{
      attestation: string,
      boottime_gpu_evidence?: GpuEvidenceBundleV1Wire[],
    }>(this.endpoint, '/v1/Attest', payload)
    throwOnRpcError(result)
    return Object.freeze({
      __name__: 'AttestResponseV1' as const,
      attestation: from_hex(result.attestation),
      boottime_gpu_evidence: to_gpu_evidence_bundles(result.boottime_gpu_evidence),
    })
  }

  /**
   * Collect GPU attestation evidence now, against a nonce you choose.
   *
   * Returns vendor-native evidence, not a verdict: select a verifier from each
   * bundle's `vendor` and `format`, then check the signature, certificate chain,
   * measurements and the embedded nonce yourself. Evidence does not by itself
   * bind the GPU to this CVM.
   *
   * @param nonce Exactly 32 bytes, passed to the GPU verbatim. SPDM fixes the
   * length; hash a longer challenge yourself.
   */
  async attestGpu(nonce: Buffer | Uint8Array): Promise<AttestGpuResponseV1> {
    if (nonce.length !== 32) {
      throw new Error(`nonce must be exactly 32 bytes, but received ${nonce.length}`)
    }
    const payload = JSON.stringify({ nonce: to_hex(nonce) })
    const result = await send_rpc_request<{
      bundles?: GpuEvidenceBundleV1Wire[],
    }>(this.endpoint, '/v1/AttestGpu', payload)
    throwOnRpcError(result)
    return Object.freeze({
      bundles: to_gpu_evidence_bundles(result.bundles),
      __name__: 'AttestGpuResponseV1' as const,
    })
  }

  /** Return this application's identity and configuration. */
  async info(): Promise<InfoResponseV1> {
    const result = await send_rpc_request<InfoResponseV1Wire>(this.endpoint, '/v1/Info', '{}')
    throwOnRpcError(result)
    return Object.freeze({
      ...result,
      app_id: from_hex(result.app_id),
      compose_hash: from_hex(result.compose_hash),
      instance_id: from_hex(result.instance_id),
      device_id: from_hex(result.device_id),
      os_image_hash: from_hex(result.os_image_hash),
      mr_aggregated: from_hex(result.mr_aggregated),
      __name__: 'InfoResponseV1' as const,
    })
  }

  /** Return the guest agent version. Also the cheapest probe for v1 support. */
  async version(): Promise<VersionResponseV1> {
    const result = await send_rpc_request<{ version: string, rev: string }>(this.endpoint, '/v1/Version', '{}')
    throwOnRpcError(result)
    return Object.freeze({
      ...result,
      __name__: 'VersionResponseV1' as const,
    })
  }
}

/**
 * The recommended client: `dstack.guest.v1`.
 *
 * This alias used to mean `DstackClientV0`. Code that upgrades without
 * changing the name fails loudly rather than quietly deriving different keys:
 * the v1 signatures differ, and `getKey` requires `algorithm` explicitly, so a
 * v0 call site stops compiling (or throws) instead of returning wrong material.
 * To stay on the frozen surface, import `DstackClientV0` by name from the
 * package root -- `client-v0` is an internal module, not an export path.
 */
export const DstackClient = DstackClientV1
export type DstackClient = DstackClientV1
