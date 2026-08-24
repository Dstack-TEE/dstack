// SPDX-FileCopyrightText: © 2024-2025 Phala Network <dstack@phala.network>
//
// SPDX-License-Identifier: Apache-2.0

import fs from 'fs'
import { send_rpc_request } from './send-rpc-request'
export { getComposeHash } from './get-compose-hash'
export { verifyEnvEncryptPublicKey, verifyEnvEncryptPublicKeyLegacy } from './verify-env-encrypt-public-key'
export type { VerifyOptions } from './verify-env-encrypt-public-key'

export interface GetTlsKeyResponse {
  __name__: Readonly<'GetTlsKeyResponse'>

  key: string
  certificate_chain: string[]

  asUint8Array: (max_length?: number) => Uint8Array
}

export interface GetKeyResponse {
  __name__: Readonly<'GetKeyResponse'>

  key: Uint8Array
  signature_chain: Uint8Array[]
}

export interface SignResponse {
  __name__: Readonly<'SignResponse'>

  signature: Uint8Array
  signature_chain: Uint8Array[]
  public_key: Uint8Array
}

export interface VerifyResponse {
  __name__: Readonly<'VerifyResponse'>

  valid: boolean
}


export type Hex = `${string}`

export type TdxQuoteHashAlgorithms =
  'sha256' | 'sha384' | 'sha512' | 'sha3-256' | 'sha3-384' | 'sha3-512' |
  'keccak256' | 'keccak384' | 'keccak512' | 'raw'

export interface EventLog {
  imr: number
  event_type: number
  digest: string
  event: string
  event_payload: string
  version?: 1 | 2
  preimage?: string
}

export interface TcbInfo {
  mrtd: string
  rtmr0: string
  rtmr1: string
  rtmr2: string
  rtmr3: string
  app_compose: string
  event_log: EventLog[]
}

export type TcbInfoV03x = TcbInfo & {
  rootfs_hash?: string
}

export type TcbInfoV05x = TcbInfo & {
  mr_aggregated: string
  os_image_hash: string
  compose_hash: string
  device_id: string
}

export interface InfoResponse<VersionTcbInfo extends TcbInfo> {
  app_id: string
  instance_id: string
  app_cert: string
  tcb_info: VersionTcbInfo
  app_name: string
  device_id: string
  mr_aggregated?: string
  os_image_hash?: string // Optional: empty if OS image is not measured by KMS
  key_provider_info: string
  compose_hash: string
  vm_config?: string
  // Cloud provider sys_vendor (e.g. "Google"). Available on dstack OS >= 0.5.7.
  cloud_vendor?: string
  // Cloud provider product_name (e.g. "Google Compute Engine"). Available on dstack OS >= 0.5.7.
  cloud_product?: string
}

export interface GetQuoteResponse {
  quote: Hex
  event_log: string
  report_data?: Hex
  vm_config?: string
}

export interface AttestResponse {
  __name__: Readonly<'AttestResponse'>

  attestation: Hex
}

export interface VersionResponse {
  __name__: Readonly<'VersionResponse'>

  version: string
  rev: string
}

export function to_hex(data: string | Buffer | Uint8Array): string {
  if (typeof data === 'string') {
    return Buffer.from(data).toString('hex');
  }
  if (data instanceof Uint8Array) {
    return Buffer.from(data).toString('hex');
  }
  return (data as Buffer).toString('hex');
}

function x509key_to_uint8array(pem: string, max_length?: number) {
  const content = pem.replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\n/g, '');
  const binaryDer = atob(content)
  if (!max_length) {
    max_length = binaryDer.length
  }
  const result = new Uint8Array(max_length)
  for (let i = 0; i < max_length; i++) {
    result[i] = binaryDer.charCodeAt(i)
  }
  return result
}

export interface TlsKeyOptions {
  path?: string;
  subject?: string;
  altNames?: string[];
  usageRaTls?: boolean;
  usageServerAuth?: boolean;
  usageClientAuth?: boolean;
  // Certificate validity start (seconds since UNIX epoch). Requires dstack OS >= 0.5.7.
  notBefore?: number;
  // Certificate validity end (seconds since UNIX epoch). Requires dstack OS >= 0.5.7.
  notAfter?: number;
  // Embed app info into the certificate. Requires dstack OS >= 0.5.7.
  withAppInfo?: boolean;
}

const SECP256K1_ALGORITHMS = new Set(['secp256k1', 'k256', ''])

/** Socket paths the clients probe, legacy first, then the namespaced variants. */
const DSTACK_SOCKET_PATHS = [
  '/var/run/dstack.sock',
  '/run/dstack.sock',
  '/var/run/dstack/dstack.sock',
  '/run/dstack/dstack.sock',
]

/**
 * A prpc handler reports failure in the response body rather than by refusing to
 * answer, so every method has to look for it; an unchecked call would hand the
 * caller a response object with every field missing.
 */
function throwOnRpcError(result: unknown): void {
  if (result && typeof result === 'object' && 'error' in result) {
    throw new Error(String((result as { error: unknown }).error))
  }
}

/**
 * Attach the byte accessor to the bundles a v1 RPC returned.
 *
 * Shared by `attest` and `attestGpu` so both hand back the same object shape,
 * which is the point of the wire message being shared.
 */
function to_gpu_evidence_bundles(
  bundles: Array<Omit<GpuEvidenceBundleV1, 'asUint8Array'>> | undefined,
): GpuEvidenceBundleV1[] {
  return (bundles ?? []).map(bundle => Object.freeze({
    ...bundle,
    asUint8Array: () => new Uint8Array(Buffer.from(bundle.evidence, 'hex')),
  }))
}

/**
 * Client for the frozen v0 guest agent surface, served at `/<Method>` and,
 * since dstack 0.6.0, equivalently at `/v0/<Method>`.
 *
 * This surface is closed at the dstack 0.5.11 shape and will not change again.
 * New capability lands in {@link DstackClientV1}, which derives *different* key
 * material for the same inputs -- the two are separate derivation trees, not
 * two spellings of one.
 */
export class DstackClientV0<T extends TcbInfo = TcbInfoV05x> {
  protected endpoint: string

  constructor(endpoint: string | undefined = undefined) {
    if (endpoint === undefined) {
      if (process.env.DSTACK_SIMULATOR_ENDPOINT) {
        console.warn(`Using simulator endpoint: ${process.env.DSTACK_SIMULATOR_ENDPOINT}`)
        endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT
      } else {
        endpoint = DSTACK_SOCKET_PATHS.find(p => fs.existsSync(p)) ?? DSTACK_SOCKET_PATHS[0]
      }
    }
    if (endpoint.startsWith('/') && !fs.existsSync(endpoint)) {
      throw new Error(`Unix socket file ${endpoint} does not exist`);
    }
    this.endpoint = endpoint
  }

  private async ensureAlgorithmSupported(algorithm: string): Promise<void> {
    if (SECP256K1_ALGORITHMS.has(algorithm)) return
    try {
      await this.version()
    } catch {
      throw new Error(`algorithm "${algorithm}" is not supported: OS version too old (Version RPC unavailable)`)
    }
  }

  private async ensureTlsKeyOptionsSupported(featureNames: string[]): Promise<void> {
    try {
      await this.version()
    } catch {
      throw new Error(`TLS key options [${featureNames.join(', ')}] are not supported: OS version too old (Version RPC unavailable)`)
    }
  }

  async getKey(path: string = '', purpose: string = '', algorithm: string = 'secp256k1'): Promise<GetKeyResponse> {
    await this.ensureAlgorithmSupported(algorithm)
    const payload = JSON.stringify({
      path: path,
      purpose: purpose,
      algorithm: algorithm
    })
    const result = await send_rpc_request<{ key: string, signature_chain: string[] }>(this.endpoint, '/GetKey', payload)
    return Object.freeze({
      key: new Uint8Array(Buffer.from(result.key, 'hex')),
      signature_chain: result.signature_chain.map(sig => new Uint8Array(Buffer.from(sig, 'hex'))),
      __name__: 'GetKeyResponse',
    })
  }

  async getTlsKey(options: TlsKeyOptions = {}): Promise<GetTlsKeyResponse> {
    const {
      subject = '',
      altNames = [],
      usageRaTls = false,
      usageServerAuth = true,
      usageClientAuth = false,
      notBefore,
      notAfter,
      withAppInfo,
    } = options;

    const newFeatures: string[] = []
    if (notBefore !== undefined) newFeatures.push('notBefore')
    if (notAfter !== undefined) newFeatures.push('notAfter')
    if (withAppInfo !== undefined) newFeatures.push('withAppInfo')
    if (newFeatures.length > 0) {
      await this.ensureTlsKeyOptionsSupported(newFeatures)
    }

    let raw: Record<string, any> = {
      subject,
      usage_ra_tls: usageRaTls,
      usage_server_auth: usageServerAuth,
      usage_client_auth: usageClientAuth,
    }
    if (altNames && altNames.length) {
      raw['alt_names'] = altNames
    }
    if (notBefore !== undefined) {
      raw['not_before'] = notBefore
    }
    if (notAfter !== undefined) {
      raw['not_after'] = notAfter
    }
    if (withAppInfo !== undefined) {
      raw['with_app_info'] = withAppInfo
    }
    const payload = JSON.stringify(raw)
    const result = await send_rpc_request<GetTlsKeyResponse>(this.endpoint, '/GetTlsKey', payload)
    const asUint8Array = (length?: number) => x509key_to_uint8array(result.key, length)
    return Object.freeze({
      ...result,
      asUint8Array,
      __name__: 'GetTlsKeyResponse',
    })
  }

  /**
   * Request a TDX quote for the given report data.
   *
   * Needs Intel TDX. Without it the guest agent returns an error and this
   * throws, and on GCP Confidential VMs it answers with the TDX quote alone,
   * leaving out the vTPM quote GCP's verification also binds. Use `attest()`
   * in both cases.
   */
  async getQuote(report_data: string | Buffer | Uint8Array): Promise<GetQuoteResponse> {
    let hex = to_hex(report_data)
    if (hex.length > 128) {
      throw new Error(`Report data is too large, it should be less than 64 bytes.`)
    }
    const payload = JSON.stringify({ report_data: hex })
    const result = await send_rpc_request<GetQuoteResponse>(this.endpoint, '/GetQuote', payload)
    if ('error' in result) {
      const err = result['error'] as string
      throw new Error(err)
    }
    return Object.freeze(result)
  }

  /**
   * Requests a versioned attestation for the given report data.
   *
   * GPU evidence is not available here: this surface is frozen at the 0.5.11
   * shape. Use {@link DstackClientV1.attest} or {@link DstackClientV1.attestGpu}.
   */
  async attest(report_data: string | Buffer | Uint8Array): Promise<AttestResponse> {
    let hex = to_hex(report_data)
    if (hex.length > 128) {
      throw new Error(`Report data is too large, it should be less than 64 bytes.`)
    }
    const payload = JSON.stringify({ report_data: hex })
    const result = await send_rpc_request<{ attestation: string }>(this.endpoint, '/Attest', payload)
    throwOnRpcError(result)
    return Object.freeze({
      __name__: 'AttestResponse',
      attestation: result.attestation as Hex,
    })
  }

  async info(): Promise<InfoResponse<T>> {
    const result = await send_rpc_request<Omit<InfoResponse<TcbInfo>, 'tcb_info'> & { tcb_info: string }>(this.endpoint, '/Info', '{}')
    return Object.freeze({
      ...result,
      tcb_info: JSON.parse(result.tcb_info) as T,
    })
  }

  /**
   * Query the guest-agent version.
   *
   * Returns the version on OS >= 0.5.7.
   * Throws on older OS versions that lack the Version RPC.
   */
  async version(): Promise<VersionResponse> {
    const result = await send_rpc_request<{ version: string, rev: string }>(this.endpoint, '/Version', '{}')
    return Object.freeze({
      ...result,
      __name__: 'VersionResponse',
    })
  }

  async isReachable(): Promise<boolean> {
    try {
      // Use info endpoint to test connectivity with 500ms timeout
      await send_rpc_request(this.endpoint, '/Info', '{}', 500)
      return true
    } catch (error) {
      return false
    }
  }

  /**
   * Emit an event. This extends the event to RTMR3 on TDX platform.
   *
   * Requires dstack OS 0.5.0 or later, and removed in 0.6.0: runtime RTMR3
   * events became system-owned, so a 0.6.0 agent answers every call with an
   * error. It stays here because the frozen surface still carries the method,
   * and the agent's own explanation is more useful than one invented here.
   *
   * @param event The event name
   * @param payload The event data as string or Buffer or Uint8Array
   */
  async emitEvent(event: string, payload: string | Buffer | Uint8Array): Promise<void> {
    if (!event) {
      throw new Error('Event name cannot be empty')
    }

    const hexPayload = to_hex(payload)
    const result = await send_rpc_request(
      this.endpoint,
      '/EmitEvent',
      JSON.stringify({
        event: event,
        payload: hexPayload
      })
    )
    throwOnRpcError(result)
  }

  /**
   * Signs a payload using a derived key.
   * @param algorithm The algorithm to use (e.g., "ed25519", "secp256k1", "secp256k1_prehashed")
   * @param data The data to sign. If algorithm is "secp256k1_prehashed", this must be a 32-byte hash.
   * @returns A SignResponse containing the signature, signature chain, and public key.
   */
  async sign(algorithm: string, data: string | Buffer | Uint8Array): Promise<SignResponse> {
    const hexData = to_hex(data);
    if (algorithm === 'secp256k1_prehashed' && hexData.length !== 64) {
        throw new Error(`Pre-hashed signing requires a 32-byte digest, but received ${hexData.length / 2} bytes`);
    }

    const payload = JSON.stringify({
        algorithm: algorithm,
        data: hexData
    });

    const result = await send_rpc_request<{ signature: string, signature_chain: string[], public_key: string }>(this.endpoint, '/Sign', payload);

    return Object.freeze({
        signature: new Uint8Array(Buffer.from(result.signature, 'hex')),
        signature_chain: result.signature_chain.map(sig => new Uint8Array(Buffer.from(sig, 'hex'))),
        public_key: new Uint8Array(Buffer.from(result.public_key, 'hex')),
        __name__: 'SignResponse',
    });
  }

  /**
   * Verifies a payload signature.
   * @param algorithm The algorithm to use (e.g., "ed25519", "secp256k1", "secp256k1_prehashed")
   * @param data The data that was signed.
   * @param signature The signature to verify.
   * @param publicKey The public key to use for verification.
   * @returns A VerifyResponse indicating if the signature is valid.
   */
  async verify(
    algorithm: string,
    data: string | Buffer | Uint8Array,
    signature: string | Buffer | Uint8Array,
    publicKey: string | Buffer | Uint8Array
  ): Promise<VerifyResponse> {
    const payload = JSON.stringify({
        algorithm: algorithm,
        data: to_hex(data),
        signature: to_hex(signature),
        public_key: to_hex(publicKey)
    });

    const result = await send_rpc_request<{ valid: boolean }>(this.endpoint, '/Verify', payload);
    throwOnRpcError(result)

    return Object.freeze({
        ...result,
        __name__: 'VerifyResponse',
    });
  }

  //
  // Legacy methods for backward compatibility with a warning to notify users about migrating to new methods.
  // These methods don't mean fully compatible as past, but we keep them here until next major version.
  //

  /**
   * @deprecated Use getKey instead.
   * @param path The path to the key.
   * @param subject The subject of the key.
   * @param altNames The alternative names of the key.
   * @returns The key.
   */
  async deriveKey(path?: string, subject?: string, altNames?: string[]): Promise<GetTlsKeyResponse> {
    throw new Error('deriveKey is deprecated, please use getKey instead.')
  }

  /**
   * @deprecated Use getQuote instead.
   * @param report_data The report data.
   * @param hash_algorithm The hash algorithm.
   * @returns The quote.
   */
  async tdxQuote(report_data: string | Buffer | Uint8Array, hash_algorithm?: TdxQuoteHashAlgorithms): Promise<GetQuoteResponse> {
    console.warn('tdxQuote is deprecated, please use getQuote instead')
    if (hash_algorithm !== "raw") {
      throw new Error('tdxQuote only supports raw hash algorithm.')
    }
    return this.getQuote(report_data)
  }
}

/**
 * @deprecated Say which surface you mean: {@link DstackClientV0} for the frozen
 * one this alias points at, or {@link DstackClientV1} for the current API.
 */
export const DstackClient = DstackClientV0
export type DstackClient<T extends TcbInfo = TcbInfoV05x> = DstackClientV0<T>

export class TappdClient extends DstackClientV0<TcbInfoV03x> {
  constructor(endpoint: string | undefined = undefined) {
    if (endpoint === undefined) {
      if (process.env.TAPPD_SIMULATOR_ENDPOINT) {
        console.warn(`Using tappd endpoint: ${process.env.TAPPD_SIMULATOR_ENDPOINT}`)
        endpoint = process.env.TAPPD_SIMULATOR_ENDPOINT
      } else {
        // Try paths in order: legacy paths first, then namespaced paths
        const socketPaths = [
          '/var/run/tappd.sock',
          '/run/tappd.sock',
          '/var/run/dstack/tappd.sock',
          '/run/dstack/tappd.sock',
        ]
        endpoint = socketPaths.find(p => fs.existsSync(p)) ?? socketPaths[0]
      }
    }
    console.warn('TappdClient is deprecated, please use DstackClient instead')
    super(endpoint)
  }

  /**
   * @deprecated Use getKey instead.
   * @param path The path to the key.
   * @param subject The subject of the key.
   * @param altNames The alternative names of the key.
   * @returns The key.
   */
  async deriveKey(path?: string, subject?: string, alt_names?: string[]): Promise<GetTlsKeyResponse> {
    console.warn('deriveKey is deprecated, please use getKey instead');
    let raw: Record<string, any> = { path: path || '', subject: subject || path || '' }
    if (alt_names && alt_names.length) {
      raw['alt_names'] = alt_names
    }
    const payload = JSON.stringify(raw)
    const result = await send_rpc_request<GetTlsKeyResponse>(this.endpoint, '/prpc/Tappd.DeriveKey', payload)
    const asUint8Array = (length?: number) => x509key_to_uint8array(result.key, length)
    return Object.freeze({
      ...result,
      asUint8Array,
      __name__: 'GetTlsKeyResponse',
    })
  }

  /**
   * @deprecated Use getQuote instead.
   * @param report_data The report data.
   * @param hash_algorithm The hash algorithm.
   * @returns The quote.
   */
  async tdxQuote(report_data: string | Buffer | Uint8Array, hash_algorithm?: TdxQuoteHashAlgorithms): Promise<GetQuoteResponse> {
    console.warn('tdxQuote is deprecated, please use getQuote instead');
    let hex = to_hex(report_data)
    if (hash_algorithm === 'raw') {
      if (hex.length > 128) {
        throw new Error(`Report data is too large, it should less then 64 bytes when hash_algorithm is raw.`)
      }
      if (hex.length < 128) {
        hex = hex.padStart(128, '0')
      }
    }
    const payload = JSON.stringify({ report_data: hex, hash_algorithm })
    const result = await send_rpc_request<GetQuoteResponse>(this.endpoint, '/prpc/Tappd.TdxQuote', payload)
    if ('error' in result) {
      const err = result['error'] as string
      throw new Error(err)
    }
    return Object.freeze(result)
  }

  async isReachable(): Promise<boolean> {
    try {
      // Use info endpoint to test connectivity with 500ms timeout
      await send_rpc_request(this.endpoint, '/prpc/Tappd.Info', '{}', 500)
      return true
    } catch (error) {
      return false
    }
  }
}

// ---------------------------------------------------------------------------
// dstack.guest.v1
// ---------------------------------------------------------------------------

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

  /** The private key the agent generated for this certificate, PEM-encoded. */
  key: string
  /** The certificate chain, leaf first, each entry PEM-encoded. */
  certificate_chain: string[]

  asUint8Array: (max_length?: number) => Uint8Array
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

  attestation: Hex

  /**
   * The GPU evidence nvattest recorded at boot, in the same bundle shape
   * {@link DstackClientV1.attestGpu} returns, so one parser serves both. Empty
   * unless the request asked for it and the guest has boot-time output --
   * absence is the empty array, not a sentinel.
   *
   * Not bound to `report_data`: nvattest ran at boot against its own nonce.
   * Bind it by replaying the runtime event log and comparing sha256 of the
   * bytes `asUint8Array()` returns against `evidence_sha256` in the measured
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
  /** Opaque vendor-native evidence bytes, hex-encoded by the JSON RPC. */
  evidence: Hex

  /**
   * The evidence as raw bytes, exactly as the vendor emitted it.
   *
   * Byte-exact by design: for a boot-time bundle the binding rule is sha256
   * over precisely these bytes, compared against `evidence_sha256` in the
   * measured `gpu-attestation` event, so parsing and re-serialising the JSON
   * breaks the comparison.
   */
  asUint8Array: () => Uint8Array
}

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
 * `mr_aggregated` are lowercase hex; the rest are plain strings, with the three
 * document fields carrying JSON owned by someone else (see `docs/guest-api-v1.md`).
 */
export interface InfoResponseV1 {
  __name__: Readonly<'InfoResponseV1'>

  app_id: Hex
  app_name: string
  compose_hash: Hex
  /**
   * The app-compose document, verbatim. `compose_hash` is sha256 over exactly
   * these bytes, so do not parse and re-serialize before hashing: key order,
   * whitespace and unknown fields all change the digest.
   */
  app_compose: string
  instance_id: Hex
  /** Identifies the host machine, not this instance. */
  device_id: Hex
  os_image_hash: Hex
  mr_aggregated: Hex
  vm_config: string
  key_provider_info: string
  cloud_vendor: string
  cloud_product: string
}

export interface VersionResponseV1 {
  __name__: Readonly<'VersionResponseV1'>

  version: string
  rev: string
}

/**
 * Client for `dstack.guest.v1`, served at `/v1/<Method>` by dstack 0.6.0 and later.
 *
 * Six methods, no more: v1 serves only what needs the TEE -- deriving keys from
 * the app root key, and attesting. `sign`, `verify`, `getQuote`, `gpuInfo` and
 * `emitEvent` are absent by design, not by oversight; see `docs/guest-api-v1.md`.
 *
 * A v1 key is NOT the v0 key of the same name. v1 derives under its own HKDF
 * salt and binds the algorithm into the derivation, so `getKey('wallet',
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
    if (endpoint === undefined) {
      if (process.env.DSTACK_SIMULATOR_ENDPOINT) {
        console.warn(`Using simulator endpoint: ${process.env.DSTACK_SIMULATOR_ENDPOINT}`)
        endpoint = process.env.DSTACK_SIMULATOR_ENDPOINT
      } else {
        endpoint = DSTACK_SOCKET_PATHS.find(p => fs.existsSync(p)) ?? DSTACK_SOCKET_PATHS[0]
      }
    }
    if (endpoint.startsWith('/') && !fs.existsSync(endpoint)) {
      throw new Error(`Unix socket file ${endpoint} does not exist`);
    }
    this.endpoint = endpoint
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
    const asUint8Array = (length?: number) => x509key_to_uint8array(result.key, length)
    return Object.freeze({
      ...result,
      asUint8Array,
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
      key: new Uint8Array(Buffer.from(result.key, 'hex')),
      public_key: new Uint8Array(Buffer.from(result.public_key, 'hex')),
      signature_chain: result.signature_chain.map(sig => new Uint8Array(Buffer.from(sig, 'hex'))),
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
      boottime_gpu_evidence?: Array<Omit<GpuEvidenceBundleV1, 'asUint8Array'>>,
    }>(this.endpoint, '/v1/Attest', payload)
    throwOnRpcError(result)
    return Object.freeze({
      __name__: 'AttestResponseV1' as const,
      attestation: result.attestation as Hex,
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
      bundles?: Array<Omit<GpuEvidenceBundleV1, 'asUint8Array'>>,
    }>(this.endpoint, '/v1/AttestGpu', payload)
    throwOnRpcError(result)
    return Object.freeze({
      bundles: to_gpu_evidence_bundles(result.bundles),
      __name__: 'AttestGpuResponseV1' as const,
    })
  }

  /** Return this application's identity and configuration. */
  async info(): Promise<InfoResponseV1> {
    const result = await send_rpc_request<Omit<InfoResponseV1, '__name__'>>(this.endpoint, '/v1/Info', '{}')
    throwOnRpcError(result)
    return Object.freeze({
      ...result,
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
